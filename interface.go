package etcdadapter

import (
	"context"

	clientv3 "go.etcd.io/etcd/client/v3"
)

type Etcd interface {
	Do(ctx context.Context, op clientv3.Op) error
}
