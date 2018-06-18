package event

type Topic string

const (
	RemovedLogsTopic Topic = "removed_logs_topic"
	ChainEventTopic Topic = "chain_event_topic"
	ChainHeadTopic Topic = "chain_head_topic"
	ChainSideTopic Topic = "chain_side_topic"
	LogTopic Topic = "log_topic"


	TxPreTopic     Topic = "tx_pre_topic"
)
