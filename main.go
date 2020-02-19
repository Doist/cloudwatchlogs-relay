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
//  cloudwatchlogs-relay -socket=/var/run/cloudwatch \
//      -group=/groupname/rsyslogd \
//      -stream='instance/${INSTANCE_ID}'
//
// This will create log group "/groupname/rsyslogd", and inside it a log stream
// "instance/${INSTANCE_ID}", where ${INSTANCE_ID} would be replaced with EC2
// instance ID. Supported placeholders for replacement are: ${HOSTNAME},
// ${INSTANCE_ID}, ${RANDOM} — for instance ID, hostname, and random string. Be
// careful to make sure placeholders are not expanded by the shell (use single
// quotes).
//
// Program requires the following IAM permissions:
//
//  {
//      "Version": "2012-10-17",
//      "Statement": [
//          {
//              "Effect": "Allow",
//              "Action": [
//                  "logs:CreateLogGroup",
//                  "logs:CreateLogStream",
//                  "logs:PutLogEvents"
//              ],
//              "Resource": "*"
//          }
//      ]
//  }
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
	"crypto/rand"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/ec2metadata"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/cloudwatchlogs"
	"golang.org/x/sync/errgroup"
)

func main() {
	args := runArgs{
		Addr: "/var/run/cloudwatch",
	}
	flag.StringVar(&args.Group, "group", args.Group, "CloudWatch Logs group name")
	flag.StringVar(&args.Stream, "stream", args.Stream, "CloudWatch Logs stream name; "+
		"supports replacements:\n${HOSTNAME}, ${INSTANCE_ID}, ${RANDOM}")
	flag.StringVar(&args.Addr, "socket", args.Addr, "path to unix socket to receive messages from rsyslogd")
	flag.Parse()
	ctx, cancel := context.WithCancel(context.Background())
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
	go func() { log.Print(<-sigCh); cancel() }()
	if err := run(ctx, args); err != nil {
		os.Stderr.WriteString(err.Error() + "\n")
		os.Exit(1)
	}
}

type runArgs struct {
	Group  string // CloudWatch Logs group name
	Stream string // CloudWatch Logs stream name
	Addr   string // path to unix socket
}

func (args *runArgs) check() error {
	if args.Group == "" {
		return errors.New("log group name must be set")
	}
	if args.Stream == "" {
		return errors.New("log stream name must be set")
	}
	if args.Addr == "" {
		return errors.New("path to unix socket must be set")
	}
	return nil
}

func run(ctx context.Context, args runArgs) error {
	if err := args.check(); err != nil {
		return err
	}
	sess, err := session.NewSession()
	if err != nil {
		return err
	}
	stream := &logStream{Group: args.Group}
	if stream.Stream, err = expandVars(sess, args.Stream); err != nil {
		return fmt.Errorf("%q expanding: %w", args.Stream, err)
	}
	svc := cloudwatchlogs.New(sess)
	group, ctx := errgroup.WithContext(ctx)
	ch := make(chan *message, 100)
	group.Go(func() error { return logFeeder(ctx, svc, stream, ch) })
	group.Go(func() error {
		pc, err := net.ListenPacket("unixgram", args.Addr)
		if err != nil {
			return err
		}
		go func() { <-ctx.Done(); pc.Close() }()
		defer pc.Close()
		defer os.Remove(args.Addr)
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
	return group.Wait()
}

func logFeeder(ctx context.Context, svc *cloudwatchlogs.CloudWatchLogs, stream *logStream, ch <-chan *message) error {
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

// expandVars expands placeholders ${HOSTNAME}, ${INSTANCE_ID}, ${RANDOM} in a
// string.
func expandVars(sess *session.Session, s string) (string, error) {
	if !strings.ContainsRune(s, '$') {
		return s, nil
	}
	var err error
	var hostname string
	var instanceID string
	var randomString string
	s = os.Expand(s, func(v string) string {
		if err != nil {
			return ""
		}
		switch v {
		case "HOSTNAME":
			if hostname != "" {
				return hostname
			}
			hostname, err = os.Hostname()
			return hostname
		case "INSTANCE_ID":
			if instanceID != "" {
				return instanceID
			}
			var meta ec2metadata.EC2InstanceIdentityDocument
			meta, err = ec2metadata.New(sess).GetInstanceIdentityDocument()
			if err != nil {
				return ""
			}
			instanceID = meta.InstanceID
			return instanceID
		case "RANDOM":
			if randomString != "" {
				return randomString
			}
			b := make([]byte, 8)
			if _, err = rand.Read(b); err != nil {
				return ""
			}
			randomString = fmt.Sprintf("%x", b)
			return randomString
		}
		return ""
	})
	return s, err
}

//go:generate sh -c "go doc > README"
