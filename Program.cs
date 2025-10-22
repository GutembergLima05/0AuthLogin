using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.Google;
using System.Threading.RateLimiting;
using static System.Net.WebRequestMethods;

var builder = WebApplication.CreateBuilder(args);


// Add services to the container.
builder.Services.AddControllers();

builder.Services.AddRateLimiter(options =>
{
    options.GlobalLimiter = PartitionedRateLimiter.Create<HttpContext, string>(httpContext =>
        RateLimitPartition.GetFixedWindowLimiter(
            partitionKey: httpContext.User.Identity?.Name ?? httpContext.Request.Headers.Host.ToString(),
            factory: partition => new FixedWindowRateLimiterOptions
            {
                AutoReplenishment = true,
                PermitLimit = 100,
                QueueLimit = 0,
                Window = TimeSpan.FromMinutes(1)
            }));

    options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
});

builder.Services.AddCors(options =>
{
    options.AddDefaultPolicy(policy =>
    {
        policy.WithOrigins(builder.Configuration["FrontUrl"] ?? "https://web.fourdevs.com.br")
              .AllowAnyMethod()
              .AllowAnyHeader()
              .AllowCredentials();
    });
});

// Configurar autenticação
builder.Services.AddAuthentication(options =>
{
    options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = GoogleDefaults.AuthenticationScheme;
})
.AddCookie(options =>
{
    options.LoginPath = "/auth/login";
    options.LogoutPath = "/auth/logout";
    options.ExpireTimeSpan = TimeSpan.FromDays(7);
    options.SlidingExpiration = true;
    options.Cookie.HttpOnly = true;
    options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
    options.Cookie.SameSite = SameSiteMode.Lax;
})
.AddGoogle(options =>
{
    options.ClientId = builder.Configuration["Authentication:Google:ClientId"] ?? throw new InvalidOperationException("Configuração de autenticação ausente");
    options.ClientSecret = builder.Configuration["Authentication:Google:ClientSecret"] ?? throw new InvalidOperationException("Configuração de autenticação ausente");
    options.SaveTokens = true;
    options.CallbackPath = "/auth/callback";

    // Escopos adicionais (opcional)
    options.Scope.Add("profile");
    options.Scope.Add("email");

    // Mapear claims
    options.ClaimActions.MapJsonKey("picture", "picture");
});

builder.Services.AddAuthorization();

// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

var app = builder.Build();

app.Use(async (context, next) =>
{
    context.Response.Headers.Append("X-Content-Type-Options", "nosniff"); // MIME type sniffing protection
    context.Response.Headers.Append("X-Frame-Options", "DENY"); // Clickjacking protection
    context.Response.Headers.Append("X-XSS-Protection", "1; mode=block"); // XSS protection
    context.Response.Headers.Append("Referrer-Policy", "strict-origin-when-cross-origin"); // Referrer policy
    context.Response.Headers.Append("Permissions-Policy", "geolocation=(), microphone=(), camera=()"); // Permissions policy
    context.Response.Headers.Append("Content-Security-Policy",
    "default-src 'self'; " +
    "script-src 'self'; " +
    "style-src 'self'; " + // Remover 'unsafe-inline'
    "img-src 'self' data: https://lh3.googleusercontent.com; " + // Para fotos do Google
    "font-src 'self'; " +
    "connect-src 'self' https://accounts.google.com; " + // Para OAuth
    "frame-ancestors 'none'; " +
    "base-uri 'self'; " +
    "form-action 'self' https://accounts.google.com;"); // Para OAuth

    await next();
});

app.UseStaticFiles();

app.UseRouting();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();

app.UseCors();

app.UseAuthentication();

app.UseRateLimiter();

app.UseAuthorization();

app.MapControllers();

app.MapFallbackToFile("index.html");

app.Run();
