// Program cloudwatchlogs-relay listens for rsyslogd messages over unix socket
// and sends messages to CloudWatch logs.
//
// To send all logged messages on a host to CloudWatch Logs, configure rsyslogd
// by creating file /etc/rsyslog.d/cloudwatch.conf with the following content:
//
//  $ModLoad omuxsock
//  $OMUxSockSocket /var/run/cloudwatch
//  *.* :omuxsock:
//
// Restart rsyslogd, and run this program like this:
//
//  cloudwatchlogs-relay -socket=/var/run/cloudwatch -name=/groupname/rsyslogd
//
// This will create log group "/groupname/rsyslogd", and inside it a log stream
// with either "rsyslogd/instance-id/${INSTANCE_ID}", or
// "rsyslogd/hostname/${HOSTNAME}" name (host name is used if instance ID
// cannot be discovered from EC2 instance metadata endpoint).
//
// Program requires the following IAM permissions:
//
//	{
//		"Version": "2012-10-17",
//		"Statement": [
//			{
//				"Effect": "Allow",
//				"Action": [
//					"logs:CreateLogGroup",
//					"logs:CreateLogStream",
//					"logs:PutLogEvents"
//				],
//				"Resource": "*"
//			}
//		]
//	}
//
// Note that while program tries to remove socket on clean shutdown, it is
// still possible that leftover socket file may be left, preventing new
// instance from starting.
//
// It relies on AWS SDK and expects to find credentials/region settings in
// usual places (IAM role, environment, configuration files).
package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/ec2metadata"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/cloudwatchlogs"
	"golang.org/x/sync/errgroup"
)

func main() {
	args := struct {
		Name string // CloudWatch Logs group name
		Addr string // path to unix socket
	}{
		Addr: "/var/run/cloudwatch",
	}
	flag.StringVar(&args.Name, "name", args.Name, "CloudWatch Logs group name")
	flag.StringVar(&args.Addr, "socket", args.Addr, "path to unix socket to receive messages from rsyslogd")
	flag.Parse()
	ctx, cancel := context.WithCancel(context.Background())
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
	go func() { log.Print(<-sigCh); cancel() }()
	if err := run(ctx, args.Name, args.Addr); err != nil {
		os.Stderr.WriteString(err.Error() + "\n")
		os.Exit(1)
	}
}

func run(ctx context.Context, name, addr string) error {
	if name == "" {
		return errors.New("log group name must be set")
	}
	if addr == "" {
		return errors.New("path to unix socket must be set")
	}
	group, ctx := errgroup.WithContext(ctx)
	ch := make(chan *message, 100)
	group.Go(func() error {
		pc, err := net.ListenPacket("unixgram", addr)
		if err != nil {
			return err
		}
		go func() { <-ctx.Done(); pc.Close() }()
		defer pc.Close()
		defer os.Remove(addr)
		b := make([]byte, 16*1024)
		var readErr error
		var n int
		for {
			if readErr != nil {
				if ctx.Err() != nil {
					return nil
				}
				return readErr
			}
			n, _, readErr = pc.ReadFrom(b)
			if n == 0 {
				continue
			}
			if b[0] != '<' {
				log.Printf("badly formatted message:\n\n%s", hex.Dump(b[:n]))
				continue
			}
			i := bytes.IndexByte(b, '>')
			msg, err := lineToMessage(b[i+1 : n])
			if err != nil {
				log.Printf("%v, message:\n\n%s", err, hex.Dump(b[:n]))
				continue
			}
			select {
			case ch <- msg:
			case <-ctx.Done():
				return nil
			}
		}
	})
	group.Go(func() error { return logFeeder(ctx, name, ch) })
	return group.Wait()
}

func logFeeder(ctx context.Context, name string, ch <-chan *message) error {
	sess, err := session.NewSession()
	if err != nil {
		return err
	}
	stream := logStream{Group: name}
	if meta, err := ec2metadata.New(sess).GetInstanceIdentityDocument(); err == nil {
		stream.Stream = "rsyslogd/instance-id/" + meta.InstanceID
	} else if name, err := os.Hostname(); err == nil {
		stream.Stream = "rsyslogd/hostname/" + name
	} else {
		return fmt.Errorf("cannot figure out neither instance id nor hostname: %w", err)
	}
	svc := cloudwatchlogs.New(sess)
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	var batch []*message
	const maxBatchSize = 100
	for {
		select {
		case <-ctx.Done():
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			return stream.sendBatch(ctx, svc, batch)
		case msg := <-ch:
			batch = append(batch, msg)
			if len(batch) < maxBatchSize {
				// if batch size reaches maxBatchSize threshold, proceed with
				// sending it instead of accumulating further
				continue
			}
		case <-ticker.C: // see logic below
		}
		if len(batch) == 0 {
			continue
		}
		if err := stream.sendBatch(ctx, svc, batch); err != nil {
			return err
		}
		if len(batch) >= maxBatchSize { // don't retain slice if it has grown too big
			batch = make([]*message, 10)
			continue
		}
		for i := range batch {
			batch[i] = nil // assist garbage collector
		}
		batch = batch[:0]
	}
}

type logStream struct {
	Group       string
	Stream      string
	token       string // SequenceToken
	initialized bool
}

func (s *logStream) createAsNeeded(ctx context.Context, svc *cloudwatchlogs.CloudWatchLogs) error {
	groupCreateInput := &cloudwatchlogs.CreateLogGroupInput{
		LogGroupName: &s.Group,
	}
	var errAlreadyExists *cloudwatchlogs.ResourceAlreadyExistsException
	if _, err := svc.CreateLogGroupWithContext(ctx, groupCreateInput); err != nil && !errors.As(err, &errAlreadyExists) {
		return err
	}
	streamCreateInput := &cloudwatchlogs.CreateLogStreamInput{
		LogGroupName:  &s.Group,
		LogStreamName: &s.Stream,
	}
	if _, err := svc.CreateLogStreamWithContext(ctx, streamCreateInput); err != nil && !errors.As(err, &errAlreadyExists) {
		return err
	}
	return nil
}

func (s *logStream) sendBatch(ctx context.Context, svc *cloudwatchlogs.CloudWatchLogs, batch []*message) error {
	if len(batch) == 0 {
		return nil
	}
	if !s.initialized {
		if err := s.createAsNeeded(ctx, svc); err != nil {
			return err
		}
		s.initialized = true
	}
	input := &cloudwatchlogs.PutLogEventsInput{
		LogGroupName:  &s.Group,
		LogStreamName: &s.Stream,
	}
	if s.token != "" {
		input.SequenceToken = &s.token
	}
	for _, msg := range batch {
		input.LogEvents = append(input.LogEvents, &cloudwatchlogs.InputLogEvent{
			Message:   &msg.text,
			Timestamp: aws.Int64(msg.time.UnixNano() / int64(time.Millisecond)),
		})
	}
	ctx2, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	out, err := svc.PutLogEventsWithContext(ctx2, input)

	// attempt to recover from continuing with already existing stream
	var errSeq *cloudwatchlogs.InvalidSequenceTokenException
	if s.token == "" && errors.As(err, &errSeq) {
		input.SequenceToken = errSeq.ExpectedSequenceToken
		out, err = svc.PutLogEventsWithContext(ctx2, input)
	}
	if err != nil {
		return err
	}
	s.token = *out.NextSequenceToken
	return nil
}

func lineToMessage(line []byte) (*message, error) {
	if len(line) <= len(time.Stamp) {
		return nil, errors.New("message is too short")
	}
	// not really interested in time provided in message as it is of a low
	// resolution, just try to parse time to be sure message has time as a
	// prefix so we can safely strip it and use current time instead, which is
	// fine because we process messages as soon as we receive them
	_, err := time.ParseInLocation(time.Stamp, string(line[:len(time.Stamp)]), time.Local)
	if err == nil {
		return &message{
			time: time.Now(),
			text: string(bytes.TrimSpace(line[len(time.Stamp):])),
		}, nil
	}
	return &message{time: time.Now(), text: string(line)}, nil
}

type message struct {
	time time.Time
	text string
}

//go:generate sh -c "go doc > README"
