using Microsoft.Data.Sqlite;
using System.Text;

var builder = WebApplication.CreateBuilder(args);
var app = builder.Build();

app.UseDefaultFiles();
app.UseStaticFiles();
app.MapGet("/", () => Results.Redirect("/signpage.html"));
// In-memory sessions (wiped on restart — fine for a learning project)
var sessions = new Dictionary<string, SessionData>();

// ---------- Database path ----------
// On Railway, the volume is mounted at /data — so the DB lives there and survives restarts.
// Locally, it falls back to the project folder so you can still debug normally.
var dbPath = Environment.GetEnvironmentVariable("DATABASE_PATH")
             ?? Path.Combine(app.Environment.ContentRootPath, "tasks.db");

// Make sure the directory exists (Railway volume is already there, but be safe)
Directory.CreateDirectory(Path.GetDirectoryName(dbPath)!);

InitializeDatabase(dbPath);

// ---------- Setup DB ----------
void InitializeDatabase(string path)
{
    using var conn = new SqliteConnection($"Data Source={path}");
    conn.Open();
    using var cmd = conn.CreateCommand();

    cmd.CommandText = @"
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at INTEGER NOT NULL
        )";
    cmd.ExecuteNonQuery();

    cmd.CommandText = @"
        CREATE TABLE IF NOT EXISTS tasks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            title TEXT NOT NULL,
            finished INTEGER NOT NULL DEFAULT 0,
            created_at INTEGER NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )";
    cmd.ExecuteNonQuery();

    // Indexes — big speedup for lookups
    cmd.CommandText = "CREATE INDEX IF NOT EXISTS idx_tasks_user ON tasks(user_id)";
    cmd.ExecuteNonQuery();
    cmd.CommandText = "CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)";
    cmd.ExecuteNonQuery();

    Console.WriteLine($"Database ready at: {path}");
}

// ---------- Helper: get user id from session cookie ----------
int? GetUserId(string? sessionId)
{
    if (sessionId is null) return null;
    return sessions.TryGetValue(sessionId, out var data) ? data.UserId : null;
}

// ---------- Helper: build task table HTML ----------
async Task<string> RenderTasksAsync(int userId)
{
    using var conn = new SqliteConnection($"Data Source={dbPath}");
    conn.Open();
    using var cmd = conn.CreateCommand();
    cmd.CommandText = "SELECT id, title, created_at, finished FROM tasks WHERE user_id = $u ORDER BY id DESC";
    cmd.Parameters.AddWithValue("$u", userId);

    using var reader = await cmd.ExecuteReaderAsync();

    var html = new StringBuilder();
    html.Append("<table class='tasks-table'>");
    html.Append("<thead><tr><th class='check-col'>Done</th><th>Task</th><th class='date-col'>Created</th><th></th></tr></thead><tbody>");

    while (await reader.ReadAsync())
    {
        var id        = reader.GetInt32(0);
        var title     = System.Net.WebUtility.HtmlEncode(reader.GetString(1));
        var createdAt = DateTimeOffset.FromUnixTimeSeconds(reader.GetInt64(2))
                                      .ToLocalTime().ToString("yyyy-MM-dd HH:mm");
        var finished  = reader.GetInt32(3) == 1;

        var rowClass = finished ? "done" : "";
        var checkedAttr = finished ? "checked" : "";

        html.Append($"""
        <tr class='{rowClass}'>
          <td class='check'>
            <label class='switch'>
              <input type='checkbox' {checkedAttr}
                     hx-post='/tasks/{id}/toggle'
                     hx-target='#tasks-container'
                     hx-swap='innerHTML'>
              <span class='slider'></span>
            </label>
          </td>
          <td class='title'>{title}</td>
          <td class='date'>{createdAt}</td>
          <td>
            <button class='bin'
                    hx-post='/tasks/{id}/delete'
                    hx-target='#tasks-container'
                    hx-swap='innerHTML'>🗑</button>
          </td>
        </tr>
        """);
    }

    html.Append("</tbody></table>");
    return html.ToString();
}

// ---------- SIGN UP ----------
app.MapPost("/signup", async (HttpRequest request) =>
{
    var form = await request.ReadFormAsync();
    var email = form["email"].ToString().Trim();
    var password = form["password"].ToString();
    var confirmPassword = form["confirmPassword"].ToString();

    if (string.IsNullOrWhiteSpace(email) || !email.Contains("@") || email.Length > 255)
        return Results.Content("<p style='color:#ff6b6b'>❌ Valid email required</p>", "text/html");

    if (password.Length < 8)
        return Results.Content("<p style='color:#ff6b6b'>❌ Password must be at least 8 characters</p>", "text/html");

    if (password != confirmPassword)
        return Results.Content("<p style='color:#ff6b6b'>❌ Passwords don't match</p>", "text/html");

    var hash = BCrypt.Net.BCrypt.HashPassword(password);
    var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();

    using var conn = new SqliteConnection($"Data Source={dbPath}");
    conn.Open();
    using var cmd = conn.CreateCommand();
    cmd.CommandText = "INSERT INTO users (email, password_hash, created_at) VALUES ($e, $h, $n)";
    cmd.Parameters.AddWithValue("$e", email);
    cmd.Parameters.AddWithValue("$h", hash);
    cmd.Parameters.AddWithValue("$n", now);

    try
    {
        await cmd.ExecuteNonQueryAsync();
        return Results.Content("<p style='color:#51cf66'>✓ Account created! Sign in now.</p>", "text/html");
    }
    catch (SqliteException ex) when (ex.SqliteErrorCode == 19)
    {
        return Results.Content("<p style='color:#ffa94d'>⚠ Email already registered</p>", "text/html");
    }
});

// ---------- SIGN IN ----------
app.MapPost("/signin", async (HttpRequest request, HttpResponse response) =>
{
    var form = await request.ReadFormAsync();
    var email = form["email"].ToString().Trim();
    var password = form["password"].ToString();

    if (string.IsNullOrWhiteSpace(email) || string.IsNullOrWhiteSpace(password))
        return Results.Content("<p style='color:#ff6b6b'>❌ Email and password required</p>", "text/html");

    using var conn = new SqliteConnection($"Data Source={dbPath}");
    conn.Open();
    using var cmd = conn.CreateCommand();
    cmd.CommandText = "SELECT id, password_hash FROM users WHERE email = $e";
    cmd.Parameters.AddWithValue("$e", email);

    using var reader = await cmd.ExecuteReaderAsync();

    if (!await reader.ReadAsync())
        return Results.Content("<p style='color:#ff6b6b'>❌ Wrong email or password</p>", "text/html");

    var userId = reader.GetInt32(0);
    var storedHash = reader.GetString(1);

    if (!BCrypt.Net.BCrypt.Verify(password, storedHash))
        return Results.Content("<p style='color:#ff6b6b'>❌ Wrong email or password</p>", "text/html");

    var sessionId = Guid.NewGuid().ToString();
    sessions[sessionId] = new SessionData { UserId = userId, CreatedAt = DateTime.UtcNow };

    response.Cookies.Append("session", sessionId, new CookieOptions
    {
        HttpOnly = true,
        Secure = app.Environment.IsProduction(),
        SameSite = SameSiteMode.Lax,
        MaxAge = TimeSpan.FromHours(24)
    });

    response.Headers.Append("HX-Redirect", "/tasks.html");
    return Results.Content("<p style='color:#51cf66'>✓ Welcome back!</p>", "text/html");
});

// ---------- SIGN OUT ----------
app.MapPost("/signout", (HttpRequest request, HttpResponse response) =>
{
    var sessionId = request.Cookies["session"];
    if (sessionId is not null) sessions.Remove(sessionId);

    response.Cookies.Delete("session");
    response.Headers.Append("HX-Redirect", "/signpage.html");
    return Results.Ok();
});

// ---------- ADD TASK ----------
app.MapPost("/tasks", async (HttpRequest request) =>
{
    var userId = GetUserId(request.Cookies["session"]);
    if (userId is null) return Results.Unauthorized();

    var form = await request.ReadFormAsync();
    var title = form["title"].ToString().Trim();

    if (string.IsNullOrWhiteSpace(title))
        return Results.Content(await RenderTasksAsync(userId.Value), "text/html");

    if (title.Length > 500) title = title[..500];

    var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();

    using var conn = new SqliteConnection($"Data Source={dbPath}");
    conn.Open();
    using var cmd = conn.CreateCommand();
    cmd.CommandText = "INSERT INTO tasks (user_id, title, created_at) VALUES ($u, $t, $n)";
    cmd.Parameters.AddWithValue("$u", userId);
    cmd.Parameters.AddWithValue("$t", title);
    cmd.Parameters.AddWithValue("$n", now);
    await cmd.ExecuteNonQueryAsync();

    return Results.Content(await RenderTasksAsync(userId.Value), "text/html");
});

// ---------- LIST TASKS ----------
app.MapGet("/tasks", async (HttpRequest request) =>
{
    var userId = GetUserId(request.Cookies["session"]);
    if (userId is null)
        return Results.Content(
            "<p style='padding:1.5rem;text-align:center;color:#c9ccd2;font-size:0.9rem'>" +
            "Session expired. Redirecting…</p>" +
            "<script>setTimeout(()=>location.href='/signpage.html',800)</script>",
            "text/html");

    return Results.Content(await RenderTasksAsync(userId.Value), "text/html");
});

// ---------- TOGGLE FINISHED ----------
app.MapPost("/tasks/{id}/toggle", async (int id, HttpRequest request) =>
{
    var userId = GetUserId(request.Cookies["session"]);
    if (userId is null) return Results.Unauthorized();

    using var conn = new SqliteConnection($"Data Source={dbPath}");
    conn.Open();
    using var cmd = conn.CreateCommand();
    cmd.CommandText = "UPDATE tasks SET finished = 1 - finished WHERE id = $id AND user_id = $u";
    cmd.Parameters.AddWithValue("$id", id);
    cmd.Parameters.AddWithValue("$u", userId);
    await cmd.ExecuteNonQueryAsync();

    return Results.Content(await RenderTasksAsync(userId.Value), "text/html");
});

// ---------- DELETE TASK ----------
app.MapPost("/tasks/{id}/delete", async (int id, HttpRequest request) =>
{
    var userId = GetUserId(request.Cookies["session"]);
    if (userId is null) return Results.Unauthorized();

    using var conn = new SqliteConnection($"Data Source={dbPath}");
    conn.Open();
    using var cmd = conn.CreateCommand();
    cmd.CommandText = "DELETE FROM tasks WHERE id = $id AND user_id = $u";
    cmd.Parameters.AddWithValue("$id", id);
    cmd.Parameters.AddWithValue("$u", userId);
    await cmd.ExecuteNonQueryAsync();

    return Results.Content(await RenderTasksAsync(userId.Value), "text/html");
});

app.Run();

// ---------- Session data shape (must be after top-level statements) ----------
public class SessionData
{
    public int UserId { get; set; }
    public DateTime CreatedAt { get; set; }
}
