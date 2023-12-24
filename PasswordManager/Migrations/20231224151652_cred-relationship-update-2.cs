using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace PasswordManager.Migrations
{
    /// <inheritdoc />
    public partial class credrelationshipupdate2 : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropForeignKey(
                name: "FK_Credentials_AspNetUsers_DeletedByUserId",
                table: "Credentials");

            migrationBuilder.DropIndex(
                name: "IX_Credentials_DeletedByUserId",
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
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
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

            migrationBuilder.CreateIndex(
                name: "IX_Credentials_DeletedByUserId",
                table: "Credentials",
                column: "DeletedByUserId");

            migrationBuilder.AddForeignKey(
                name: "FK_Credentials_AspNetUsers_DeletedByUserId",
                table: "Credentials",
                column: "DeletedByUserId",
                principalTable: "AspNetUsers",
                principalColumn: "Id");
        }
    }
}
