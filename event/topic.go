package event

type Topic string

const (
	ChainHeadTopic Topic = "chain_head_topic"
	TxPreTopic Topic = "tx_pre_topic"
)
