using AlertaSP.Core.Enums;
using AlertaSP.Core.Interfaces.Security;
using AlertaSP.Security.Risk;
using Microsoft.Extensions.Options;
using Xunit;

namespace AlertaSP.SecurityTests.Risk;

public class CitizenRiskCalculatorTests
{
    private readonly ICitizenRiskCalculator _calculator =
        new CitizenRiskCalculator(Options.Create(new CitizenRiskOptions { CitizenRiskK = 30.0 }));

    private static IncidentCount Sanitized(DataCategory category, DataSensitivity sensitivity, int count = 1) =>
        new(category, sensitivity, IncidentResult.Sanitized, count);

    private static IncidentCount Blocked(DataCategory category, DataSensitivity sensitivity, int count = 1) =>
        new(category, sensitivity, IncidentResult.Blocked, count);

    [Fact]
    public void NoIncidents_ScoreIsZeroAndVeryLow()
    {
        var score = _calculator.Calculate(Array.Empty<IncidentCount>());

        Assert.Equal(0, score.Score);
        Assert.Equal(0.0, score.RawExposure);
        Assert.Equal(0, score.IncidentCount);
        Assert.Equal("Muito baixo", score.Classification);
    }

    [Fact]
    public void KnownInput_FollowsTheDocumentedFormula()
    {
        // Um CPF mascarado: 4 (alta) × 1,2 (dado pessoal) × 0,5 (sanitizado) = 2,4
        // Uma credencial bloqueada: 8 (crítica) × 1,5 (credencial) × 0,3 (bloqueado) = 3,6
        var score = _calculator.Calculate(new[]
        {
            Sanitized(DataCategory.PersonalData, DataSensitivity.High),
            Blocked(DataCategory.Credentials, DataSensitivity.Critical)
        });

        Assert.Equal(6.0, score.RawExposure);
        Assert.Equal((int)Math.Round(100 * (1 - Math.Exp(-6.0 / 30.0))), score.Score);
        Assert.Equal(18, score.Score);
        Assert.Equal(2, score.IncidentCount);
    }

    [Fact]
    public void GroupedCounts_WeighTheSameAsIndividualIncidents()
    {
        var individual = _calculator.Calculate(new[]
        {
            Blocked(DataCategory.HealthData, DataSensitivity.High),
            Blocked(DataCategory.HealthData, DataSensitivity.High),
            Blocked(DataCategory.HealthData, DataSensitivity.High)
        });
        var grouped = _calculator.Calculate(new[] { Blocked(DataCategory.HealthData, DataSensitivity.High, count: 3) });

        Assert.Equal(individual.RawExposure, grouped.RawExposure);
        Assert.Equal(individual.Score, grouped.Score);
    }

    [Fact]
    public void NewIncident_NeverLowersTheScore()
    {
        var incidents = new List<IncidentCount>();
        var previous = 0;

        foreach (var category in new[] { DataCategory.Location, DataCategory.PersonalData, DataCategory.Credentials, DataCategory.HealthData })
        {
            incidents.Add(Blocked(category, DataSensitivity.Low));
            var current = _calculator.Calculate(incidents).Score;

            Assert.True(current >= previous, $"O risco caiu de {previous} para {current} ao entrar um incidente de {category}.");
            previous = current;
        }
    }

    [Fact]
    public void ManyIncidents_ApproachButNeverExceed100()
    {
        var score = _calculator.Calculate(new[] { Blocked(DataCategory.Credentials, DataSensitivity.Critical, count: 50) });

        Assert.InRange(score.Score, 81, 100);
        Assert.Equal("Crítico", score.Classification);
    }

    [Fact]
    public void BlockedAttempt_WeighsLessThanAnEffectiveExposure()
    {
        var blocked = _calculator.Calculate(new[] { Blocked(DataCategory.Credentials, DataSensitivity.Critical) });
        var exposed = _calculator.Calculate(new[]
        {
            new IncidentCount(DataCategory.Credentials, DataSensitivity.Critical, IncidentResult.AllowedWithViolation, 1)
        });

        Assert.True(blocked.RawExposure < exposed.RawExposure);
    }

    [Theory]
    [InlineData(0, "Muito baixo")]
    [InlineData(20, "Muito baixo")]
    [InlineData(21, "Baixo")]
    [InlineData(40, "Baixo")]
    [InlineData(41, "Moderado")]
    [InlineData(60, "Moderado")]
    [InlineData(61, "Alto")]
    [InlineData(80, "Alto")]
    [InlineData(81, "Crítico")]
    [InlineData(100, "Crítico")]
    public void Classification_FollowsTheDocumentedBands(int score, string expected)
    {
        Assert.Equal(expected, CitizenRiskCalculator.Classify(score));
    }
}
