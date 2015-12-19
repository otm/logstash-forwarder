package main

// KinesisPublisher is used for sending through a AWS Kinesis stream
type KinesisPublisher struct {
}

// Run will process input events and call registrar when done
func (k *KinesisPublisher) Run(input chan []*FileEvent, registrar chan []*FileEvent) {

}
