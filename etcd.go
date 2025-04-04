package etcdadapter

import (
	"context"
	"errors"

	clientv3 "go.etcd.io/etcd/client/v3"
)

type etcdTxn struct {
	ifOps   []clientv3.Cmp
	thenOps []clientv3.Op
	elseOps []clientv3.Op
}

func (t *etcdTxn) Do(ctx context.Context, op clientv3.Op) error {
	t.Then(ctx, op)
	return nil
}

func (t *etcdTxn) If(_ context.Context, op ...clientv3.Cmp) {
	t.ifOps = append(t.ifOps, op...)
}

func (t *etcdTxn) Then(_ context.Context, op ...clientv3.Op) {
	t.thenOps = append(t.thenOps, op...)
}

func (t *etcdTxn) Else(_ context.Context, op ...clientv3.Op) {
	t.elseOps = append(t.elseOps, op...)
}

func (t *etcdTxn) Commit(ctx context.Context, conn *clientv3.Client) error {
	resp, err := conn.Txn(ctx).If(t.ifOps...).Then(t.thenOps...).Else(t.elseOps...).Commit()
	if err != nil {
		return err
	}

	if !resp.Succeeded {
		return errors.New("transaction failed")
	}

	return nil
}

type etcdClient struct {
	client *clientv3.Client
}

func (c *etcdClient) Do(ctx context.Context, op clientv3.Op) error {
	if _, err := c.client.Do(ctx, op); err != nil {
		return err
	}
	return nil
}
