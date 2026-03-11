package grpc

import (
	"context"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	"apex/teamserver/internal/tasks"
	pb "apex/teamserver/pkg/proto/apexpb"
)

type TaskServiceServer struct {
	pb.UnimplementedTaskServiceServer
	queue *tasks.Queue
}

func NewTaskServiceServer(queue *tasks.Queue) *TaskServiceServer {
	return &TaskServiceServer{queue: queue}
}

func (s *TaskServiceServer) CreateTask(ctx context.Context, req *pb.CreateTaskRequest) (*pb.Task, error) {
	claims, ok := ClaimsFromContext(ctx)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "missing claims")
	}

	t, err := s.queue.Enqueue(ctx, req.AgentId, claims.OperatorID, req.Command, req.Arguments)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "enqueue task: %v", err)
	}

	return taskToProto(t), nil
}

func (s *TaskServiceServer) GetTask(_ context.Context, _ *pb.GetTaskRequest) (*pb.Task, error) {
	return nil, status.Error(codes.Unimplemented, "not yet implemented")
}

func (s *TaskServiceServer) ListTasks(_ context.Context, _ *pb.ListTasksRequest) (*pb.ListTasksResponse, error) {
	return nil, status.Error(codes.Unimplemented, "not yet implemented")
}

func (s *TaskServiceServer) CancelTask(_ context.Context, _ *pb.CancelTaskRequest) (*pb.Task, error) {
	return nil, status.Error(codes.Unimplemented, "not yet implemented")
}

func (s *TaskServiceServer) StreamTaskResults(req *pb.StreamTaskResultsRequest, stream pb.TaskService_StreamTaskResultsServer) error {
	ch := s.queue.SubscribeResults(stream.Context(), req.AgentId)
	for {
		select {
		case <-stream.Context().Done():
			return nil
		case result, ok := <-ch:
			if !ok {
				return nil
			}
			if err := stream.Send(taskResultToProto(result)); err != nil {
				return err
			}
		}
	}
}

func taskToProto(t *tasks.Task) *pb.Task {
	p := &pb.Task{
		Id:         t.ID,
		AgentId:    t.AgentID,
		OperatorId: t.OperatorID,
		Command:    t.Command,
		Arguments:  t.Arguments,
		Status:     taskStatusToProto(t.Status),
		CreatedAt:  timestamppb.New(t.CreatedAt),
	}
	if !t.CompletedAt.IsZero() {
		p.CompletedAt = timestamppb.New(t.CompletedAt)
	}
	return p
}

func taskResultToProto(r *tasks.TaskResult) *pb.TaskResult {
	return &pb.TaskResult{
		TaskId:    r.TaskID,
		AgentId:   r.AgentID,
		Output:    r.Output,
		Success:   r.Success,
		Error:     r.Error,
		Timestamp: timestamppb.New(r.Timestamp),
	}
}

func taskStatusToProto(s tasks.Status) pb.TaskStatus {
	switch s {
	case tasks.StatusQueued:
		return pb.TaskStatus_TASK_STATUS_QUEUED
	case tasks.StatusDelivered:
		return pb.TaskStatus_TASK_STATUS_DELIVERED
	case tasks.StatusCompleted:
		return pb.TaskStatus_TASK_STATUS_COMPLETED
	case tasks.StatusFailed:
		return pb.TaskStatus_TASK_STATUS_FAILED
	case tasks.StatusCancelled:
		return pb.TaskStatus_TASK_STATUS_CANCELLED
	default:
		return pb.TaskStatus_TASK_STATUS_UNKNOWN
	}
}
