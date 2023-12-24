using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace PasswordManager.Migrations
{
    /// <inheritdoc />
    public partial class credrelationshipupdate : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<DateTime>(
                name: "CreatedAt",
                table: "Credentials",
                type: "timestamp with time zone",
                nullable: false,
                defaultValue: new DateTime(1, 1, 1, 0, 0, 0, 0, DateTimeKind.Unspecified));

            migrationBuilder.AddColumn<string>(
                name: "CreatedByUserId",
                table: "Credentials",
                type: "text",
                nullable: false,
                defaultValue: "");

            migrationBuilder.AddColumn<DateTime>(
                name: "DeletedAt",
                table: "Credentials",
                type: "timestamp with time zone",
                nullable: true);

            migrationBuilder.AddColumn<DateTime>(
                name: "DeletedBy",
                table: "Credentials",
                type: "timestamp with time zone",
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "DeletedByUserId",
                table: "Credentials",
                type: "text",
                nullable: true);

            migrationBuilder.AddColumn<DateTime>(
                name: "LastUpdatedAt",
                table: "Credentials",
                type: "timestamp with time zone",
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "LastUpdatedByUserId",
                table: "Credentials",
                type: "text",
                nullable: true);

            migrationBuilder.CreateIndex(
                name: "IX_Credentials_DeletedByUserId",
                table: "Credentials",
                column: "DeletedByUserId");

            migrationBuilder.CreateIndex(
                name: "IX_Credentials_LastUpdatedByUserId",
                table: "Credentials",
                column: "LastUpdatedByUserId");

            migrationBuilder.AddForeignKey(
                name: "FK_Credentials_AspNetUsers_DeletedByUserId",
                table: "Credentials",
                column: "DeletedByUserId",
                principalTable: "AspNetUsers",
                principalColumn: "Id");

            migrationBuilder.AddForeignKey(
                name: "FK_Credentials_AspNetUsers_LastUpdatedByUserId",
                table: "Credentials",
                column: "LastUpdatedByUserId",
                principalTable: "AspNetUsers",
                principalColumn: "Id");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropForeignKey(
                name: "FK_Credentials_AspNetUsers_DeletedByUserId",
                table: "Credentials");

            migrationBuilder.DropForeignKey(
                name: "FK_Credentials_AspNetUsers_LastUpdatedByUserId",
                table: "Credentials");

            migrationBuilder.DropIndex(
                name: "IX_Credentials_DeletedByUserId",
                table: "Credentials");

            migrationBuilder.DropIndex(
                name: "IX_Credentials_LastUpdatedByUserId",
                table: "Credentials");

            migrationBuilder.DropColumn(
                name: "CreatedAt",
                table: "Credentials");

            migrationBuilder.DropColumn(
                name: "CreatedByUserId",
                table: "Credentials");

            migrationBuilder.DropColumn(
                name: "DeletedAt",
                table: "Credentials");

            migrationBuilder.DropColumn(
                name: "DeletedBy",
                table: "Credentials");

            migrationBuilder.DropColumn(
                name: "DeletedByUserId",
                table: "Credentials");

            migrationBuilder.DropColumn(
                name: "LastUpdatedAt",
                table: "Credentials");

            migrationBuilder.DropColumn(
                name: "LastUpdatedByUserId",
                table: "Credentials");
        }
    }
}
