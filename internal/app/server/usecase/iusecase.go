package usecase

import "http-proxy-server/internal/app/server/pkg/models"

type IUseCase interface {
	GetRequestById(id int64) (*models.Request, error)
	GetRequestDataById(id int64) (*models.RequestData, error)
	GetAllRequestsData() ([]*models.RequestData, error)
	SaveRequest(request *models.Request) error
	SaveResponse(response *models.Response) error
	ScanRequest()
}
