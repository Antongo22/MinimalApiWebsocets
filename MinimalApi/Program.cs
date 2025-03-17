using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using System.Collections.Concurrent;
using System.Net.WebSockets;
using System.Security.Claims;
using System.Text;
using System.Text.Json;

var builder = WebApplication.CreateBuilder(args);

// Настройка CORS с поддержкой кук
builder.Services.AddCors(options =>
{
    options.AddPolicy("AllowSpecificOrigin", policy =>
    {
        policy.WithOrigins("http://localhost:5000")
              .AllowAnyHeader()
              .AllowAnyMethod()
              .AllowCredentials(); // [[1]]
    });
});

// Аутентификация
builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
    .AddCookie(options =>
    {
        options.LoginPath = "/login";
        options.AccessDeniedPath = "/login";
    }); // [[3]]

builder.Services.AddAuthorization();

var app = builder.Build();

app.UseCors("AllowSpecificOrigin");
app.UseAuthentication();
app.UseAuthorization();
app.UseStaticFiles();
app.UseWebSockets();

// Демо-база пользователей
var users = new Dictionary<string, string>
{
    {"user1", "password1"},
    {"user2", "password2"},
    {"user3", "password3"}
};

// Хранение глобальных сообщений
var globalMessages = new List<string>();

// WebSocket-сессии
var userSessions = new ConcurrentDictionary<string, WebSocket>();

app.MapGet("/", () => Results.Redirect("/login"));

// Защищенный маршрут /chat
app.MapGet("/chat", async (HttpContext context) =>
{
    var username = context.User.Identity?.Name;
    if (string.IsNullOrEmpty(username))
        return Results.Redirect("/login");

    var html = await File.ReadAllTextAsync("wwwroot/chat.html");
    html = html.Replace("{{username}}", username);
    return Results.Text(html, "text/html");
}).RequireAuthorization(); // [[8]]

app.MapGet("/login", async (HttpContext context) =>
{
    context.Response.ContentType = "text/html";
    await context.Response.SendFileAsync("wwwroot/login.html"); // [[6]]
});

app.MapPost("/login", async (HttpContext context) =>
{
    var form = await context.Request.ReadFormAsync();
    var username = form["username"];
    var password = form["password"];

    if (users.TryGetValue(username, out var pwd) && pwd == password)
    {
        await context.SignInAsync(
            CookieAuthenticationDefaults.AuthenticationScheme,
            new ClaimsPrincipal(new ClaimsIdentity(
                new[] { new Claim(ClaimTypes.Name, username) },
                CookieAuthenticationDefaults.AuthenticationScheme))
        );
        return Results.Redirect("/chat");
    }

    return Results.Redirect("/login?error=1");
});

app.MapGet("/logout", async (HttpContext context) =>
{
    await context.SignOutAsync();
    return Results.Redirect("/login");
});

// WebSocket endpoint
app.MapGet("/ws", async (HttpContext context) =>
{
    if (!context.WebSockets.IsWebSocketRequest)
        return Results.BadRequest();

    var username = context.User.Identity?.Name;
    if (string.IsNullOrEmpty(username))
        return Results.Unauthorized();

    using var ws = await context.WebSockets.AcceptWebSocketAsync();
    userSessions.TryAdd(username, ws);

    // Отправляем историю при подключении
    foreach (var msg in globalMessages)
    {
        await ws.SendAsync(Encoding.UTF8.GetBytes(msg),
            WebSocketMessageType.Text, true, CancellationToken.None);
    }

    await HandleWebSocketConnection(ws, username);
    return Results.Empty;
});

async Task HandleWebSocketConnection(WebSocket ws, string username)
{
    var buffer = new byte[1024 * 4];
    try
    {
        while (ws.State == WebSocketState.Open)
        {
            var result = await ws.ReceiveAsync(new ArraySegment<byte>(buffer), CancellationToken.None);
            if (result.MessageType == WebSocketMessageType.Text)
            {
                var message = Encoding.UTF8.GetString(buffer, 0, result.Count);
                await ProcessMessage(message, username);
            }
        }
    }
    finally
    {
        userSessions.TryRemove(username, out _);
        await ws.CloseAsync(WebSocketCloseStatus.NormalClosure, "Closed", CancellationToken.None);
    }
}

async Task ProcessMessage(string jsonMessage, string sender)
{
    var message = JsonSerializer.Deserialize<ChatMessage>(jsonMessage);
    if (message?.Type == "global")
    {
        var fullMessage = $"{sender}: {message.Text}";
        globalMessages.Add(fullMessage);
        await BroadcastGlobalMessage(fullMessage);
    }
}

async Task BroadcastGlobalMessage(string message)
{
    foreach (var (user, ws) in userSessions)
    {
        if (ws.State == WebSocketState.Open)
        {
            await ws.SendAsync(Encoding.UTF8.GetBytes(message),
                WebSocketMessageType.Text, true, CancellationToken.None);
        }
    }
}

app.Run();

public record ChatMessage(string Type, string Text);