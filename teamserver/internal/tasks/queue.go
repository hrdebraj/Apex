package tasks

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"github.com/rs/zerolog/log"
)

type Status string

const (
	StatusQueued    Status = "queued"
	StatusDelivered Status = "delivered"
	StatusCompleted Status = "completed"
	StatusFailed    Status = "failed"
	StatusCancelled Status = "cancelled"
)

type Task struct {
	ID          string    `json:"id"`
	AgentID     string    `json:"agent_id"`
	OperatorID  string    `json:"operator_id"`
	Command     string    `json:"command"`
	Arguments   []byte    `json:"arguments,omitempty"`
	Status      Status    `json:"status"`
	CreatedAt   time.Time `json:"created_at"`
	CompletedAt time.Time `json:"completed_at,omitempty"`
}

type TaskResult struct {
	TaskID    string    `json:"task_id"`
	AgentID   string    `json:"agent_id"`
	Output    []byte    `json:"output"`
	Success   bool      `json:"success"`
	Error     string    `json:"error,omitempty"`
	Timestamp time.Time `json:"timestamp"`
}

type Queue struct {
	rdb *redis.Client
}

func NewQueue(rdb *redis.Client) *Queue {
	return &Queue{rdb: rdb}
}

func taskQueueKey(agentID string) string {
	return fmt.Sprintf("apex:tasks:%s", agentID)
}

func taskResultChannel(agentID string) string {
	return fmt.Sprintf("apex:results:%s", agentID)
}

func (q *Queue) Enqueue(ctx context.Context, agentID, operatorID, command string, args []byte) (*Task, error) {
	task := &Task{
		ID:         uuid.New().String(),
		AgentID:    agentID,
		OperatorID: operatorID,
		Command:    command,
		Arguments:  args,
		Status:     StatusQueued,
		CreatedAt:  time.Now(),
	}

	data, err := json.Marshal(task)
	if err != nil {
		return nil, fmt.Errorf("marshal task: %w", err)
	}

	if err := q.rdb.RPush(ctx, taskQueueKey(agentID), data).Err(); err != nil {
		return nil, fmt.Errorf("enqueue task: %w", err)
	}

	log.Debug().
		Str("task_id", task.ID).
		Str("agent_id", agentID).
		Str("command", command).
		Msg("Task enqueued")

	return task, nil
}

// Dequeue retrieves all pending tasks for an agent (called during check-in).
func (q *Queue) Dequeue(ctx context.Context, agentID string) ([]*Task, error) {
	key := taskQueueKey(agentID)
	results, err := q.rdb.LRange(ctx, key, 0, -1).Result()
	if err != nil {
		return nil, fmt.Errorf("dequeue tasks: %w", err)
	}

	if len(results) == 0 {
		return nil, nil
	}

	q.rdb.Del(ctx, key)

	tasks := make([]*Task, 0, len(results))
	for _, raw := range results {
		var t Task
		if err := json.Unmarshal([]byte(raw), &t); err != nil {
			log.Warn().Err(err).Msg("Failed to unmarshal task from queue")
			continue
		}
		t.Status = StatusDelivered
		tasks = append(tasks, &t)
	}
	return tasks, nil
}

func (q *Queue) PublishResult(ctx context.Context, result *TaskResult) error {
	data, err := json.Marshal(result)
	if err != nil {
		return fmt.Errorf("marshal result: %w", err)
	}

	channel := taskResultChannel(result.AgentID)
	if err := q.rdb.Publish(ctx, channel, data).Err(); err != nil {
		return fmt.Errorf("publish result: %w", err)
	}
	return nil
}

func (q *Queue) SubscribeResults(ctx context.Context, agentID string) <-chan *TaskResult {
	ch := make(chan *TaskResult, 64)
	sub := q.rdb.Subscribe(ctx, taskResultChannel(agentID))

	go func() {
		defer close(ch)
		defer sub.Close()

		for msg := range sub.Channel() {
			var result TaskResult
			if err := json.Unmarshal([]byte(msg.Payload), &result); err != nil {
				log.Warn().Err(err).Msg("Failed to unmarshal task result")
				continue
			}
			ch <- &result
		}
	}()

	return ch
}
