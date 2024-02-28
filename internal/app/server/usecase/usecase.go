package usecase

import (
	"http-proxy-server/internal/app/server/pkg/models"
	"http-proxy-server/internal/app/server/repository"
)

type ProxyUseCase struct {
	proxyRepository repository.IRepository
}

func NewProxyUseCase(proxyRepository repository.IRepository) IUseCase {
	return &ProxyUseCase{
		proxyRepository: proxyRepository,
	}
}

func (u *ProxyUseCase) GetRequestDataById(id int64) (*models.RequestData, error) {
	return u.proxyRepository.GetRequestDataById(id)
}

func (u *ProxyUseCase) GetRequestById(id int64) (*models.Request, error) {
	return u.proxyRepository.GetRequestById(id)
}

func (u *ProxyUseCase) GetAllRequestsData() ([]*models.RequestData, error) {
	return u.proxyRepository.GetAllRequestsData()
}

func (u *ProxyUseCase) SaveRequest(request *models.Request) error {
	return u.proxyRepository.InsertRequest(request)
}

func (u *ProxyUseCase) SaveResponse(response *models.Response) error {
	return u.proxyRepository.InsertResponse(response)
}

func (u *ProxyUseCase) ScanRequest() {
	panic("implement me")
}
