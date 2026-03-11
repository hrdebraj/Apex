package grpc

import (
	"context"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	"apex/teamserver/internal/auth"
	pb "apex/teamserver/pkg/proto/apexpb"
)

type AuthServiceServer struct {
	pb.UnimplementedAuthServiceServer
	authSvc *auth.Service
}

func NewAuthServiceServer(authSvc *auth.Service) *AuthServiceServer {
	return &AuthServiceServer{authSvc: authSvc}
}

func (s *AuthServiceServer) Login(ctx context.Context, req *pb.LoginRequest) (*pb.LoginResponse, error) {
	token, op, err := s.authSvc.Login(ctx, req.Username, req.Password)
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, "invalid credentials")
	}

	return &pb.LoginResponse{
		AccessToken: token,
		Operator:    operatorToProto(op),
	}, nil
}

func (s *AuthServiceServer) Logout(ctx context.Context, _ *pb.LogoutRequest) (*pb.Empty, error) {
	return &pb.Empty{}, nil
}

func (s *AuthServiceServer) RefreshToken(_ context.Context, _ *pb.RefreshTokenRequest) (*pb.RefreshTokenResponse, error) {
	return nil, status.Error(codes.Unimplemented, "not yet implemented")
}

func (s *AuthServiceServer) GetCurrentOperator(ctx context.Context, _ *pb.Empty) (*pb.Operator, error) {
	claims, ok := ClaimsFromContext(ctx)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "missing claims")
	}

	return &pb.Operator{
		Id:       claims.OperatorID,
		Username: claims.Username,
		Role:     roleToProto(claims.Role),
	}, nil
}

func (s *AuthServiceServer) CreateOperator(ctx context.Context, req *pb.CreateOperatorRequest) (*pb.Operator, error) {
	claims, ok := ClaimsFromContext(ctx)
	if !ok || claims.Role != auth.RoleAdmin {
		return nil, status.Error(codes.PermissionDenied, "admin only")
	}

	role := protoToRole(req.Role)
	op, err := s.authSvc.CreateOperator(ctx, req.Username, req.Password, role)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "create operator: %v", err)
	}

	return operatorToProto(op), nil
}

func (s *AuthServiceServer) ListOperators(_ context.Context, _ *pb.Empty) (*pb.ListOperatorsResponse, error) {
	return nil, status.Error(codes.Unimplemented, "not yet implemented")
}

func (s *AuthServiceServer) DeleteOperator(_ context.Context, _ *pb.DeleteOperatorRequest) (*pb.Empty, error) {
	return nil, status.Error(codes.Unimplemented, "not yet implemented")
}

func operatorToProto(op *auth.Operator) *pb.Operator {
	p := &pb.Operator{
		Id:       op.ID,
		Username: op.Username,
		Role:     roleToProto(op.Role),
	}
	if !op.CreatedAt.IsZero() {
		p.CreatedAt = timestamppb.New(op.CreatedAt)
	}
	if !op.LastLogin.IsZero() {
		p.LastLogin = timestamppb.New(op.LastLogin)
	}
	return p
}

func roleToProto(r auth.Role) pb.OperatorRole {
	switch r {
	case auth.RoleAdmin:
		return pb.OperatorRole_OPERATOR_ROLE_ADMIN
	case auth.RoleOperator:
		return pb.OperatorRole_OPERATOR_ROLE_OPERATOR
	case auth.RoleReadOnly:
		return pb.OperatorRole_OPERATOR_ROLE_READONLY
	default:
		return pb.OperatorRole_OPERATOR_ROLE_UNKNOWN
	}
}

func protoToRole(r pb.OperatorRole) auth.Role {
	switch r {
	case pb.OperatorRole_OPERATOR_ROLE_ADMIN:
		return auth.RoleAdmin
	case pb.OperatorRole_OPERATOR_ROLE_OPERATOR:
		return auth.RoleOperator
	case pb.OperatorRole_OPERATOR_ROLE_READONLY:
		return auth.RoleReadOnly
	default:
		return auth.RoleOperator
	}
}
