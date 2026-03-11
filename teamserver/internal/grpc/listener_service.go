package grpc

import (
	"context"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"apex/teamserver/internal/listeners"
	pb "apex/teamserver/pkg/proto/apexpb"
)

type ListenerServiceServer struct {
	pb.UnimplementedListenerServiceServer
	mgr *listeners.Manager
}

func NewListenerServiceServer(mgr *listeners.Manager) *ListenerServiceServer {
	return &ListenerServiceServer{mgr: mgr}
}

func (s *ListenerServiceServer) CreateListener(ctx context.Context, req *pb.CreateListenerRequest) (*pb.Listener, error) {
	cfg := listeners.Config{
		Name:        req.Name,
		Protocol:    protoToListenerProtocol(req.Protocol),
		BindAddress: req.BindAddress,
		BindPort:    int(req.BindPort),
		Options:     req.Config,
	}

	l, err := s.mgr.Create(cfg)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "create listener: %v", err)
	}

	return listenerToProto(l), nil
}

func (s *ListenerServiceServer) GetListener(_ context.Context, req *pb.GetListenerRequest) (*pb.Listener, error) {
	l, ok := s.mgr.Get(req.Id)
	if !ok {
		return nil, status.Error(codes.NotFound, "listener not found")
	}
	return listenerToProto(l), nil
}

func (s *ListenerServiceServer) ListListeners(_ context.Context, _ *pb.Empty) (*pb.ListListenersResponse, error) {
	all := s.mgr.List()
	result := make([]*pb.Listener, len(all))
	for i, l := range all {
		result[i] = listenerToProto(l)
	}
	return &pb.ListListenersResponse{Listeners: result}, nil
}

func (s *ListenerServiceServer) StartListener(ctx context.Context, req *pb.StartListenerRequest) (*pb.Listener, error) {
	if err := s.mgr.Start(ctx, req.Id); err != nil {
		return nil, status.Errorf(codes.Internal, "start listener: %v", err)
	}
	l, _ := s.mgr.Get(req.Id)
	return listenerToProto(l), nil
}

func (s *ListenerServiceServer) StopListener(ctx context.Context, req *pb.StopListenerRequest) (*pb.Listener, error) {
	if err := s.mgr.Stop(ctx, req.Id); err != nil {
		return nil, status.Errorf(codes.Internal, "stop listener: %v", err)
	}
	l, _ := s.mgr.Get(req.Id)
	return listenerToProto(l), nil
}

func (s *ListenerServiceServer) DeleteListener(ctx context.Context, req *pb.DeleteListenerRequest) (*pb.Empty, error) {
	if err := s.mgr.Delete(ctx, req.Id); err != nil {
		return nil, status.Errorf(codes.Internal, "delete listener: %v", err)
	}
	return &pb.Empty{}, nil
}

func (s *ListenerServiceServer) StreamListenerEvents(_ *pb.Empty, _ pb.ListenerService_StreamListenerEventsServer) error {
	return status.Error(codes.Unimplemented, "not yet implemented")
}

func listenerToProto(l listeners.Listener) *pb.Listener {
	st := pb.Status_STATUS_INACTIVE
	if l.IsRunning() {
		st = pb.Status_STATUS_ACTIVE
	}
	return &pb.Listener{
		Id:          l.ID(),
		Name:        l.Name(),
		Protocol:    listenerProtocolToProto(l.Protocol()),
		BindAddress: l.BindAddress(),
		BindPort:    int32(l.BindPort()),
		Status:      st,
	}
}

func protoToListenerProtocol(p pb.ListenerProtocol) listeners.Protocol {
	switch p {
	case pb.ListenerProtocol_LISTENER_PROTOCOL_HTTP:
		return listeners.ProtocolHTTP
	case pb.ListenerProtocol_LISTENER_PROTOCOL_HTTPS:
		return listeners.ProtocolHTTPS
	case pb.ListenerProtocol_LISTENER_PROTOCOL_DNS:
		return listeners.ProtocolDNS
	case pb.ListenerProtocol_LISTENER_PROTOCOL_TCP:
		return listeners.ProtocolTCP
	case pb.ListenerProtocol_LISTENER_PROTOCOL_SMB:
		return listeners.ProtocolSMB
	default:
		return listeners.ProtocolHTTP
	}
}

func listenerProtocolToProto(p listeners.Protocol) pb.ListenerProtocol {
	switch p {
	case listeners.ProtocolHTTP:
		return pb.ListenerProtocol_LISTENER_PROTOCOL_HTTP
	case listeners.ProtocolHTTPS:
		return pb.ListenerProtocol_LISTENER_PROTOCOL_HTTPS
	case listeners.ProtocolDNS:
		return pb.ListenerProtocol_LISTENER_PROTOCOL_DNS
	case listeners.ProtocolTCP:
		return pb.ListenerProtocol_LISTENER_PROTOCOL_TCP
	case listeners.ProtocolSMB:
		return pb.ListenerProtocol_LISTENER_PROTOCOL_SMB
	default:
		return pb.ListenerProtocol_LISTENER_PROTOCOL_UNKNOWN
	}
}
