using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace AlertaSP.Infrastructure.Migrations
{
    /// <inheritdoc />
    public partial class EncryptRouteLocation : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            // Trajetos gravados antes desta versão estão em texto claro e não podem ser cifrados por SQL
            // (a chave fica no Data Protection, fora do banco). São removidos junto com seus alertas.
            migrationBuilder.Sql("DELETE FROM \"Alerts\";");
            migrationBuilder.Sql("DELETE FROM \"Routes\";");

            migrationBuilder.DropColumn(
                name: "Destination",
                table: "Routes");

            migrationBuilder.DropColumn(
                name: "DestinationLatitude",
                table: "Routes");

            migrationBuilder.DropColumn(
                name: "DestinationLongitude",
                table: "Routes");

            migrationBuilder.DropColumn(
                name: "Origin",
                table: "Routes");

            migrationBuilder.DropColumn(
                name: "OriginLatitude",
                table: "Routes");

            migrationBuilder.DropColumn(
                name: "OriginLongitude",
                table: "Routes");

            migrationBuilder.AddColumn<string>(
                name: "EncryptedCoordinates",
                table: "Routes",
                type: "TEXT",
                nullable: false,
                defaultValue: "");

            migrationBuilder.AddColumn<string>(
                name: "EncryptedDestination",
                table: "Routes",
                type: "TEXT",
                nullable: false,
                defaultValue: "");

            migrationBuilder.AddColumn<string>(
                name: "EncryptedOrigin",
                table: "Routes",
                type: "TEXT",
                nullable: false,
                defaultValue: "");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "EncryptedCoordinates",
                table: "Routes");

            migrationBuilder.DropColumn(
                name: "EncryptedDestination",
                table: "Routes");

            migrationBuilder.DropColumn(
                name: "EncryptedOrigin",
                table: "Routes");

            migrationBuilder.AddColumn<string>(
                name: "Destination",
                table: "Routes",
                type: "TEXT",
                maxLength: 500,
                nullable: false,
                defaultValue: "");

            migrationBuilder.AddColumn<double>(
                name: "DestinationLatitude",
                table: "Routes",
                type: "REAL",
                nullable: false,
                defaultValue: 0.0);

            migrationBuilder.AddColumn<double>(
                name: "DestinationLongitude",
                table: "Routes",
                type: "REAL",
                nullable: false,
                defaultValue: 0.0);

            migrationBuilder.AddColumn<string>(
                name: "Origin",
                table: "Routes",
                type: "TEXT",
                maxLength: 500,
                nullable: false,
                defaultValue: "");

            migrationBuilder.AddColumn<double>(
                name: "OriginLatitude",
                table: "Routes",
                type: "REAL",
                nullable: false,
                defaultValue: 0.0);

            migrationBuilder.AddColumn<double>(
                name: "OriginLongitude",
                table: "Routes",
                type: "REAL",
                nullable: false,
                defaultValue: 0.0);
        }
    }
}
