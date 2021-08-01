using System;
using Microsoft.EntityFrameworkCore.Migrations;

namespace ExternalIdentityServerAspNetIdentity.Data.Migrations.IdentityServer.ApplicationDb
{
    public partial class UserSignupRequest : Migration
    {
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "UserSignupRequests",
                columns: table => new
                {
                    EmailValidationToken = table.Column<Guid>(nullable: false),
                    Email = table.Column<string>(nullable: false),
                    IsEmailValidationTokenUsed = table.Column<bool>(nullable: false),
                    ExpireOnUtc = table.Column<DateTimeOffset>(nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_UserSignupRequests", x => x.EmailValidationToken);
                });
        }

        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "UserSignupRequests");
        }
    }
}
