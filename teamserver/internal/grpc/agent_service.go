package grpc

import (
	"context"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	"apex/teamserver/internal/agents"
	pb "apex/teamserver/pkg/proto/apexpb"
)

type AgentServiceServer struct {
	pb.UnimplementedAgentServiceServer
	mgr *agents.Manager
}

func NewAgentServiceServer(mgr *agents.Manager) *AgentServiceServer {
	return &AgentServiceServer{mgr: mgr}
}

func (s *AgentServiceServer) ListAgents(_ context.Context, _ *pb.Empty) (*pb.ListAgentsResponse, error) {
	all := s.mgr.List()
	result := make([]*pb.Agent, len(all))
	for i, a := range all {
		result[i] = agentToProto(a)
	}
	return &pb.ListAgentsResponse{Agents: result}, nil
}

func (s *AgentServiceServer) GetAgent(_ context.Context, req *pb.GetAgentRequest) (*pb.Agent, error) {
	a, ok := s.mgr.Get(req.Id)
	if !ok {
		return nil, status.Error(codes.NotFound, "agent not found")
	}
	return agentToProto(a), nil
}

func (s *AgentServiceServer) RemoveAgent(ctx context.Context, req *pb.RemoveAgentRequest) (*pb.Empty, error) {
	if err := s.mgr.Remove(ctx, req.Id); err != nil {
		return nil, status.Errorf(codes.Internal, "remove agent: %v", err)
	}
	return &pb.Empty{}, nil
}

func (s *AgentServiceServer) StreamAgentEvents(_ *pb.Empty, stream pb.AgentService_StreamAgentEventsServer) error {
	ch := s.mgr.Subscribe()

	for {
		select {
		case <-stream.Context().Done():
			return nil
		case event, ok := <-ch:
			if !ok {
				return nil
			}
			pbEvent := &pb.AgentEvent{
				EventType: string(event.Type),
			}
			if a, ok := event.Data.(*agents.Agent); ok {
				pbEvent.Agent = agentToProto(a)
			}
			if err := stream.Send(pbEvent); err != nil {
				return err
			}
		}
	}
}

func agentToProto(a *agents.Agent) *pb.Agent {
	st := pb.Status_STATUS_INACTIVE
	if a.Alive {
		st = pb.Status_STATUS_ACTIVE
	}
	return &pb.Agent{
		Id:          a.ID,
		Hostname:    a.Hostname,
		Username:    a.Username,
		Os:          a.OS,
		Arch:        a.Arch,
		Pid:         int32(a.PID),
		ProcessName: a.ProcessName,
		InternalIp:  a.InternalIP,
		ExternalIp:  a.ExternalIP,
		Sleep:       int32(a.Sleep),
		Jitter:      int32(a.Jitter),
		ListenerId:  a.ListenerID,
		FirstSeen:   timestamppb.New(a.FirstSeen),
		LastSeen:    timestamppb.New(a.LastSeen),
		Status:      st,
	}
}
