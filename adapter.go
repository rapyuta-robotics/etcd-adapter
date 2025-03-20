// etcdadapter will simulate the table structure of Relational DB in ETCD which is a kv-based storage.
// Under a basic path, we will build a key for each policy, and the value is the Json format string for each Casbin Rule.

package etcdadapter

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/casbin/casbin/v2"
	"github.com/casbin/casbin/v2/model"
	"github.com/casbin/casbin/v2/persist"
	client "go.etcd.io/etcd/client/v3"
)

const (
	// DialTimeout is the timeout for failing to establish a connection.
	DIALTIMEOUT = 5 * time.Second

	// DialKeepAliveTime is the time after which client pings the server to see if
	// transport is alive.
	DIALKEEPALIVETIME = 5 * time.Second

	REQUESTTIMEOUT = 500 * time.Second

	// DialKeepAliveTimeout is the time that the client waits for a response for the
	// keep-alive probe. If the response is not received in this time, the connection is closed.
	DIALKEEPALIVETIMEOUT = 10 * time.Second

	// PLACEHOLDER represent the NULL value in the Casbin Rule.
	PLACEHOLDER = "_"

	// DEFAULT_KEY is the root path in ETCD, if not provided.
	DEFAULT_KEY = "casbin_policy"
)

type CasbinRule struct {
	Key   string `json:"key"`
	PType string `json:"ptype"`
	V0    string `json:"v0"`
	V1    string `json:"v1"`
	V2    string `json:"v2"`
	V3    string `json:"v3"`
	V4    string `json:"v4"`
	V5    string `json:"v5"`
}

// Adapter represents the ETCD adapter for policy storage.
type Adapter struct {
	etcdEndpoints []string
	key           string

	// etcd connection client
	conn Etcd

	transactionMu *sync.Mutex
}

func NewAdapter(etcdEndpoints []string, key string) *Adapter {
	if key == "" {
		key = DEFAULT_KEY
	}
	a := &Adapter{
		etcdEndpoints: etcdEndpoints,
		key:           key,
		transactionMu: new(sync.Mutex),
	}
	a.connect()

	// Call the destructor when the object is released.
	runtime.SetFinalizer(a, finalizer)

	return a
}

func (a *Adapter) connect() {
	etcdConf := client.Config{
		Endpoints:            a.etcdEndpoints,
		DialTimeout:          DIALTIMEOUT,
		DialKeepAliveTimeout: DIALKEEPALIVETIMEOUT,
		DialKeepAliveTime:    DIALKEEPALIVETIME,
	}

	connection, err := client.New(etcdConf)
	if err != nil {
		panic(err)
	}

	a.conn = &etcdClient{client: connection}

	if err = a.createRootKey(connection); err != nil {
		panic(err)
	}
}

// finalizer is the destructor for Adapter.
func finalizer(a *Adapter) {
	conn, ok := a.conn.(*etcdClient)
	if !ok {
		return
	}

	conn.client.Close()
}

// createRootKey creates the root key if it doesn't exist
func (a *Adapter) createRootKey(c *client.Client) error {
	ctx, cancel := context.WithTimeout(context.Background(), REQUESTTIMEOUT)
	defer cancel()

	getResp, err := c.Get(ctx, a.key)
	if err != nil {
		return err
	}

	if getResp.Count > 0 {
		return nil
	}

	_, err = c.Put(ctx, a.key, "0")
	if err != nil {
		return err
	}

	return nil
}

func (a *Adapter) close() {
	conn := a.conn.(*etcdClient).client
	conn.Close()
}

// LoadPolicy loads all policies from etcd
func (a *Adapter) LoadPolicy(model model.Model) error {
	var rule CasbinRule

	conn, ok := a.conn.(*etcdClient)
	if !ok {
		return errors.New("not supported inside a transaction")
	}

	ctx, cancel := context.WithTimeout(context.Background(), REQUESTTIMEOUT)
	defer cancel()

	getResp, err := conn.client.Get(ctx, a.getRootKey(), client.WithPrefix())
	if err != nil {
		return err
	}

	if len(getResp.Kvs) == 0 {
		return nil
	}

	for _, kv := range getResp.Kvs {
		if err := json.Unmarshal(kv.Value, &rule); err != nil {
			return err
		}

		a.loadPolicy(rule, model)
	}
	return nil
}

func (a *Adapter) getRootKey() string {
	return fmt.Sprintf("/%s", a.key)
}

func (a *Adapter) loadPolicy(rule CasbinRule, model model.Model) {
	var line strings.Builder
	line.WriteString(rule.PType)

	if rule.V0 != "" {
		line.WriteString(", ")
		line.WriteString(rule.V0)
	}
	if rule.V1 != "" {
		line.WriteString(", ")
		line.WriteString(rule.V1)
	}
	if rule.V2 != "" {
		line.WriteString(", ")
		line.WriteString(rule.V2)
	}
	if rule.V3 != "" {
		line.WriteString(", ")
		line.WriteString(rule.V3)
	}
	if rule.V4 != "" {
		line.WriteString(", ")
		line.WriteString(rule.V4)
	}
	if rule.V5 != "" {
		line.WriteString(", ")
		line.WriteString(rule.V5)
	}

	persist.LoadPolicyLine(line.String(), model)
}

// SavePolicy will rewrite all of policies in ETCD with the current data in Casbin
func (a *Adapter) SavePolicy(model model.Model) error {
	// clean old rule data
	a.destroy()

	var rules []CasbinRule

	for ptype, ast := range model["p"] {
		for _, line := range ast.Policy {
			rules = append(rules, a.convertRule(ptype, line))
		}
	}

	for ptype, ast := range model["g"] {
		for _, line := range ast.Policy {
			rules = append(rules, a.convertRule(ptype, line))
		}
	}

	return a.savePolicy(rules)
}

// destroy or clean all of policy
func (a *Adapter) destroy() error {
	conn := a.conn.(*etcdClient).client
	ctx, cancel := context.WithTimeout(context.Background(), REQUESTTIMEOUT)
	defer cancel()
	_, err := conn.Do(ctx, client.OpDelete(a.getRootKey(), client.WithPrefix()))
	return err
}

func (a *Adapter) convertRule(ptype string, line []string) (rule CasbinRule) {
	rule = CasbinRule{}
	rule.PType = ptype
	policys := []string{ptype}
	length := len(line)

	if len(line) > 0 {
		rule.V0 = line[0]
		policys = append(policys, line[0])
	}
	if len(line) > 1 {
		rule.V1 = line[1]
		policys = append(policys, line[1])
	}
	if len(line) > 2 {
		rule.V2 = line[2]
		policys = append(policys, line[2])
	}
	if len(line) > 3 {
		rule.V3 = line[3]
		policys = append(policys, line[3])
	}
	if len(line) > 4 {
		rule.V4 = line[4]
		policys = append(policys, line[4])
	}
	if len(line) > 5 {
		rule.V5 = line[5]
		policys = append(policys, line[5])
	}

	for i := 0; i < 6-length; i++ {
		policys = append(policys, PLACEHOLDER)
	}

	rule.Key = strings.Join(policys, "::")

	return rule
}

func (a *Adapter) savePolicy(rules []CasbinRule) error {
	ctx, cancel := context.WithTimeout(context.Background(), REQUESTTIMEOUT)
	defer cancel()
	for _, rule := range rules {
		ruleData, _ := json.Marshal(rule)
		err := a.conn.Do(ctx, client.OpPut(a.constructPath(rule.Key), string(ruleData)))
		if err != nil {
			return err
		}
	}
	return nil
}

func (a *Adapter) constructPath(key string) string {
	return fmt.Sprintf("/%s/%s", a.key, key)
}

// AddPolicy adds a policy rule to the storage.
// Part of the Auto-Save feature.
func (a *Adapter) AddPolicy(sec string, ptype string, line []string) error {
	rule := a.convertRule(ptype, line)
	ctx, cancel := context.WithTimeout(context.Background(), REQUESTTIMEOUT)
	defer cancel()
	ruleData, _ := json.Marshal(rule)
	err := a.conn.Do(ctx, client.OpPut(a.constructPath(rule.Key), string(ruleData)))
	return err
}

// RemovePolicy removes a policy rule from the storage.
// Part of the Auto-Save feature.
func (a *Adapter) RemovePolicy(sec string, ptype string, line []string) error {
	rule := a.convertRule(ptype, line)
	ctx, cancel := context.WithTimeout(context.Background(), REQUESTTIMEOUT)
	defer cancel()
	err := a.conn.Do(ctx, client.OpDelete(a.constructPath(rule.Key)))
	return err
}

// UpdatePolicy updates a policy rule to the storage.
// Part of the Auto-Save feature.
func (a *Adapter) UpdatePolicy(sec string, ptype string, oldRule, newPolicy []string) error {
	oldPolicy := a.convertRule(ptype, oldRule)
	newRule := a.convertRule(ptype, newPolicy)
	newRuleData, _ := json.Marshal(newRule)

	ctx, cancel := context.WithTimeout(context.Background(), REQUESTTIMEOUT)
	defer cancel()

	txn, commit := a.getTransaction()

	txn.If(ctx, client.Compare(client.CreateRevision(a.constructPath(oldPolicy.Key)), ">", 0))
	txn.Then(ctx,
		client.OpDelete(a.constructPath(oldPolicy.Key)),
		client.OpPut(a.constructPath(newRule.Key), string(newRuleData)),
	)
	txn.Else(ctx, client.OpPut(a.constructPath(newRule.Key), string(newRuleData)))

	return commit(ctx)
}

// AddPolicies adds a list of policy rules to the storage
func (a *Adapter) AddPolicies(sec string, ptype string, rules [][]string) error {
	ctx, cancel := context.WithTimeout(context.Background(), REQUESTTIMEOUT)
	defer cancel()

	txn, commit := a.getTransaction()

	ruleMap := make(map[string]struct{})

	for _, r := range rules {
		// Rule out duplicates from the request
		hash := strings.Join(r, "")
		if _, ok := ruleMap[hash]; ok {
			continue
		}
		ruleMap[hash] = struct{}{}

		rule := a.convertRule(ptype, r)
		ruleData, _ := json.Marshal(rule)
		txn.Then(ctx, client.OpPut(a.constructPath(rule.Key), string(ruleData)))
	}

	return commit(ctx)
}

// RemovePolicies removes a list of policy rules from the storage
func (a *Adapter) RemovePolicies(sec string, ptype string, rules [][]string) error {
	ctx, cancel := context.WithTimeout(context.Background(), REQUESTTIMEOUT)
	defer cancel()

	txn, commit := a.getTransaction()

	ruleMap := make(map[string]struct{})

	for _, r := range rules {
		// Rule out duplicates from the request
		hash := strings.Join(r, "")
		if _, ok := ruleMap[hash]; ok {
			continue
		}
		ruleMap[hash] = struct{}{}

		rule := a.convertRule(ptype, r)
		txn.Then(ctx, client.OpDelete(a.constructPath(rule.Key)))
	}

	return commit(ctx)
}

// UpdatePolicies updates a list of policy rules to the storage
func (a *Adapter) UpdatePolicies(sec string, ptype string, oldRules, newRules [][]string) error {
	if len(oldRules) != len(newRules) {
		return errors.New("UpdatePolicies: oldRules and newRules did not match")
	}

	_, cancel := context.WithTimeout(context.Background(), REQUESTTIMEOUT)
	defer cancel()

	ruleMap := make(map[string]struct{})

	for i := 0; i < len(oldRules); i++ {
		// Rule out duplicates from the request
		hash := strings.Join(oldRules[i], "")
		if _, ok := ruleMap[hash]; ok {
			continue
		}

		ruleMap[hash] = struct{}{}

		if a.UpdatePolicy(sec, ptype, oldRules[i], newRules[i]) != nil {
			continue
		}
	}

	return nil
}

// RemoveFilteredPolicy removes policy rules that match the filter from the storage.
// Part of the Auto-Save feature.
func (a *Adapter) RemoveFilteredPolicy(sec string, ptype string, fieldIndex int, fieldValues ...string) error {
	rule := CasbinRule{}

	rule.PType = ptype
	if fieldIndex <= 0 && 0 < fieldIndex+len(fieldValues) {
		rule.V0 = fieldValues[0-fieldIndex]
	}
	if fieldIndex <= 1 && 1 < fieldIndex+len(fieldValues) {
		rule.V1 = fieldValues[1-fieldIndex]
	}
	if fieldIndex <= 2 && 2 < fieldIndex+len(fieldValues) {
		rule.V2 = fieldValues[2-fieldIndex]
	}
	if fieldIndex <= 3 && 3 < fieldIndex+len(fieldValues) {
		rule.V3 = fieldValues[3-fieldIndex]
	}
	if fieldIndex <= 4 && 4 < fieldIndex+len(fieldValues) {
		rule.V4 = fieldValues[4-fieldIndex]
	}
	if fieldIndex <= 5 && 5 < fieldIndex+len(fieldValues) {
		rule.V5 = fieldValues[5-fieldIndex]
	}

	filter := a.constructFilter(rule)

	return a.removeFilteredPolicy(filter)
}

func (a *Adapter) constructFilter(rule CasbinRule) string {
	var filter string
	if rule.PType != "" {
		filter = fmt.Sprintf("/%s/%s", a.key, rule.PType)
	} else {
		filter = fmt.Sprintf("/%s/.*", a.key)
	}

	if rule.V0 != "" {
		filter = fmt.Sprintf("%s::%s", filter, rule.V0)
	} else {
		filter = fmt.Sprintf("%s::.*", filter)
	}

	if rule.V1 != "" {
		filter = fmt.Sprintf("%s::%s", filter, rule.V1)
	} else {
		filter = fmt.Sprintf("%s::.*", filter)
	}

	if rule.V2 != "" {
		filter = fmt.Sprintf("%s::%s", filter, rule.V2)
	} else {
		filter = fmt.Sprintf("%s::.*", filter)
	}

	if rule.V3 != "" {
		filter = fmt.Sprintf("%s::%s", filter, rule.V3)
	} else {
		filter = fmt.Sprintf("%s::.*", filter)
	}

	if rule.V4 != "" {
		filter = fmt.Sprintf("%s::%s", filter, rule.V4)
	} else {
		filter = fmt.Sprintf("%s::.*", filter)
	}

	if rule.V5 != "" {
		filter = fmt.Sprintf("%s::%s", filter, rule.V5)
	} else {
		filter = fmt.Sprintf("%s::.*", filter)
	}

	return filter
}

func (a *Adapter) removeFilteredPolicy(filter string) error {
	conn := a.conn.(*etcdClient).client
	ctx, cancel := context.WithTimeout(context.Background(), REQUESTTIMEOUT)
	defer cancel()
	// get all policy key
	g, err := conn.Do(ctx, client.OpGet(a.constructPath(""), client.WithPrefix(), client.WithKeysOnly()))
	if err != nil {
		return err
	}

	getResp := g.Get()
	var filteredKeys []string
	for _, kv := range getResp.Kvs {
		matched, err := regexp.MatchString(filter, string(kv.Key))
		if err != nil {
			return err
		}
		if matched {
			filteredKeys = append(filteredKeys, string(kv.Key))
		}
	}

	for _, key := range filteredKeys {
		err = a.conn.Do(ctx, client.OpDelete(key))
		if err != nil {
			return err
		}
	}
	return nil
}

// UpdateFilteredPolicies updates policy rules that match the filter from the storage.
// Part of the Auto-Save feature.
func (a *Adapter) UpdateFilteredPolicies(sec string, ptype string, newPolicies [][]string, fieldIndex int, fieldValues ...string) ([][]string, error) {
	rule := CasbinRule{}

	rule.PType = ptype
	if fieldIndex <= 0 && 0 < fieldIndex+len(fieldValues) {
		rule.V0 = fieldValues[0-fieldIndex]
	}
	if fieldIndex <= 1 && 1 < fieldIndex+len(fieldValues) {
		rule.V1 = fieldValues[1-fieldIndex]
	}
	if fieldIndex <= 2 && 2 < fieldIndex+len(fieldValues) {
		rule.V2 = fieldValues[2-fieldIndex]
	}
	if fieldIndex <= 3 && 3 < fieldIndex+len(fieldValues) {
		rule.V3 = fieldValues[3-fieldIndex]
	}
	if fieldIndex <= 4 && 4 < fieldIndex+len(fieldValues) {
		rule.V4 = fieldValues[4-fieldIndex]
	}
	if fieldIndex <= 5 && 5 < fieldIndex+len(fieldValues) {
		rule.V5 = fieldValues[5-fieldIndex]
	}

	filter := a.constructFilter(rule)

	return newPolicies, a.updateFilteredPolicies(ptype, filter, newPolicies)
}

func (a *Adapter) updateFilteredPolicies(ptype string, filter string, newPolicies [][]string) error {
	conn := a.conn.(*etcdClient).client
	ctx, cancel := context.WithTimeout(context.Background(), REQUESTTIMEOUT)
	defer cancel()

	txn, commit := a.getTransaction()
	txn.If(ctx, client.Compare(client.CreateRevision(a.key), ">", 0))

	getResp, err := conn.Get(ctx, a.constructPath(""), client.WithPrefix(), client.WithKeysOnly())
	if err != nil {
		return err
	}

	var thenOps []client.Op
	for _, kv := range getResp.Kvs {
		matched, err := regexp.MatchString(filter, string(kv.Key))
		if err != nil {
			return err
		}
		if matched {
			thenOps = append(thenOps, client.OpDelete(a.constructPath(string(kv.Key))))
		}
	}

	for _, rule := range newPolicies {
		newPolicy := a.convertRule(ptype, rule)
		newRuleData, _ := json.Marshal(newPolicy)

		thenOps = append(thenOps, client.OpPut(a.constructPath(newPolicy.Key), string(newRuleData)))
	}
	return commit(ctx)
}

func (a *Adapter) Transaction(e casbin.IEnforcer, fc func(casbin.IEnforcer) error) error {
	a.transactionMu.Lock()
	defer a.transactionMu.Unlock()

	txn, commit := a.getTransaction()

	defer func() {
		e.SetAdapter(a.Copy())

		// Check if this is needed.
		if err := e.LoadPolicy(); err != nil {
			panic(err)
		}
	}()

	b := a.Copy()
	b.conn = txn
	copyEnforcer := e
	copyEnforcer.SetAdapter(b)

	ctx, cancel := context.WithTimeout(context.Background(), REQUESTTIMEOUT)
	defer cancel()

	if err := fc(copyEnforcer); err != nil {
		return err
	}

	return commit(ctx)
}

func (a *Adapter) Copy() *Adapter {
	return &Adapter{
		etcdEndpoints: a.etcdEndpoints,
		key:           a.key,
		conn:          a.conn,
	}
}

func (a *Adapter) getTransaction() (*etcdTxn, func(context.Context) error) {
	var (
		txn      *etcdTxn
		isClient bool
	)

	switch client := a.conn.(type) {
	case *etcdClient:
		isClient = true
		txn = &etcdTxn{}
	case *etcdTxn:
		txn = client
	}

	return txn, func(ctx context.Context) error {
		if !isClient {
			return nil
		}

		return txn.Commit(ctx, a.conn.(*etcdClient).client)
	}
}
