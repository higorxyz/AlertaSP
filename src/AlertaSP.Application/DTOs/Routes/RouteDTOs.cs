using System.ComponentModel.DataAnnotations;
using AlertaSP.Core.Attributes;
using AlertaSP.Core.Enums;

namespace AlertaSP.Application.DTOs.Routes;

public class CreateRouteRequest
{
    [Range(1, int.MaxValue, ErrorMessage = "Informe o Id de um cidadão cadastrado.")]
    public int CitizenId { get; set; }

    [Required(ErrorMessage = "O nome do trajeto é obrigatório.")]
    [StringLength(200, MinimumLength = 2, ErrorMessage = "O nome deve ter entre 2 e 200 caracteres.")]
    public string Name { get; set; } = string.Empty;

    [Required(ErrorMessage = "A origem é obrigatória.")]
    [StringLength(500, ErrorMessage = "A origem deve ter no máximo 500 caracteres.")]
    [Sensitive(DataCategory.Location)]
    public string Origin { get; set; } = string.Empty;

    [Required(ErrorMessage = "O destino é obrigatório.")]
    [StringLength(500, ErrorMessage = "O destino deve ter no máximo 500 caracteres.")]
    [Sensitive(DataCategory.Location)]
    public string Destination { get; set; } = string.Empty;

    [Range(-90.0, 90.0, ErrorMessage = "Latitude de origem deve estar entre -90 e 90.")]
    [Sensitive(DataCategory.Location)]
    public double OriginLatitude { get; set; }

    [Range(-180.0, 180.0, ErrorMessage = "Longitude de origem deve estar entre -180 e 180.")]
    [Sensitive(DataCategory.Location)]
    public double OriginLongitude { get; set; }

    [Range(-90.0, 90.0, ErrorMessage = "Latitude de destino deve estar entre -90 e 90.")]
    [Sensitive(DataCategory.Location)]
    public double DestinationLatitude { get; set; }

    [Range(-180.0, 180.0, ErrorMessage = "Longitude de destino deve estar entre -180 e 180.")]
    [Sensitive(DataCategory.Location)]
    public double DestinationLongitude { get; set; }
}

public class UpdateRouteRequest
{
    [Required(ErrorMessage = "O nome do trajeto é obrigatório.")]
    [StringLength(200, MinimumLength = 2, ErrorMessage = "O nome deve ter entre 2 e 200 caracteres.")]
    public string Name { get; set; } = string.Empty;

    [Required(ErrorMessage = "A origem é obrigatória.")]
    [StringLength(500, ErrorMessage = "A origem deve ter no máximo 500 caracteres.")]
    [Sensitive(DataCategory.Location)]
    public string Origin { get; set; } = string.Empty;

    [Required(ErrorMessage = "O destino é obrigatório.")]
    [StringLength(500, ErrorMessage = "O destino deve ter no máximo 500 caracteres.")]
    [Sensitive(DataCategory.Location)]
    public string Destination { get; set; } = string.Empty;

    [Range(-90.0, 90.0, ErrorMessage = "Latitude de origem deve estar entre -90 e 90.")]
    [Sensitive(DataCategory.Location)]
    public double OriginLatitude { get; set; }

    [Range(-180.0, 180.0, ErrorMessage = "Longitude de origem deve estar entre -180 e 180.")]
    [Sensitive(DataCategory.Location)]
    public double OriginLongitude { get; set; }

    [Range(-90.0, 90.0, ErrorMessage = "Latitude de destino deve estar entre -90 e 90.")]
    [Sensitive(DataCategory.Location)]
    public double DestinationLatitude { get; set; }

    [Range(-180.0, 180.0, ErrorMessage = "Longitude de destino deve estar entre -180 e 180.")]
    [Sensitive(DataCategory.Location)]
    public double DestinationLongitude { get; set; }
}

public class ToggleMonitoringRequest
{
    public bool IsActive { get; set; }
}

public class RouteResponse
{
    public int Id { get; init; }
    public int CitizenId { get; init; }
    public string Name { get; init; } = string.Empty;
    public string Origin { get; init; } = string.Empty;
    public string Destination { get; init; } = string.Empty;
    public double OriginLatitude { get; init; }
    public double OriginLongitude { get; init; }
    public double DestinationLatitude { get; init; }
    public double DestinationLongitude { get; init; }
    public bool IsMonitoringActive { get; init; }
    public DateTime CreatedAt { get; init; }
}
