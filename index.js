require('dotenv').config();
const express = require('express');
const path = require('path');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
  max: 5,
});

const JWT_SECRET = process.env.JWT_SECRET || 'doan2_smart_home_gateway_secret';
const app = express();
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// ================= KHỞI TẠO DATABASE & ADMIN MẶC ĐỊNH =================
async function initDatabase() {
  try {
    // 1. Tạo bảng Hẹn giờ (Schedules)
    await pool.query(`
      CREATE TABLE IF NOT EXISTS schedules (
        id SERIAL PRIMARY KEY,
        relay_id INT NOT NULL,
        action BOOLEAN NOT NULL,
        schedule_time VARCHAR(5) NOT NULL,
        repeat_days VARCHAR(50) DEFAULT 'daily',
        enabled BOOLEAN DEFAULT true,
        last_triggered_date VARCHAR(20),
        created_at TIMESTAMP DEFAULT NOW()
      );
    `);

    // 2. Tạo bảng Trạng thái phần cứng & Mạng (SD Card, Ethernet/Wi-Fi, Tốc độ mạng)
    await pool.query(`
      CREATE TABLE IF NOT EXISTS gateway_status (
        id INT PRIMARY KEY DEFAULT 1,
        connection_mode VARCHAR(20) DEFAULT 'wifi',
        preferred_mode VARCHAR(20) DEFAULT 'auto',
        net_speed_mbps REAL DEFAULT 0,
        rssi INT DEFAULT 0,
        ip_address VARCHAR(50) DEFAULT '0.0.0.0',
        sd_total_mb REAL DEFAULT 1024,
        sd_used_mb REAL DEFAULT 0,
        last_seen TIMESTAMP DEFAULT NOW()
      );
    `);
    await pool.query(`INSERT INTO gateway_status (id) VALUES (1) ON CONFLICT (id) DO NOTHING;`);

    // 3. Tạo bảng Cấu hình Wi-Fi từ xa cho ESP32
    await pool.query(`
      CREATE TABLE IF NOT EXISTS wifi_config (
        id INT PRIMARY KEY DEFAULT 1,
        ssid VARCHAR(100) DEFAULT '',
        password VARCHAR(100) DEFAULT '',
        pending_update BOOLEAN DEFAULT false,
        updated_at TIMESTAMP DEFAULT NOW()
      );
    `);
    await pool.query(`INSERT INTO wifi_config (id) VALUES (1) ON CONFLICT (id) DO NOTHING;`);

    // 4. Tài khoản Admin mặc định
    const { rows } = await pool.query("SELECT id FROM users WHERE username = 'admin'");
    if (rows.length === 0) {
      const hash = await bcrypt.hash('123456', 10);
      await pool.query(
        `INSERT INTO users (username, password_hash, full_name, role, can_relay_1, can_relay_2)
         VALUES ($1, $2, $3, 'admin', true, true)`,
        ['admin', hash, 'Quản trị viên (Lâm Phi Hùng)']
      );
      console.log('[INIT] Đã tạo tài khoản mặc định: admin / 123456');
    }
    console.log('[INIT] Database đã sẵn sàng.');
  } catch (err) {
    console.error('Lỗi khởi tạo Database:', err.message);
  }
}
initDatabase();

// ================= BỘ ĐẾM HẸN GIỜ THỜI GIAN THỰC (GIỜ VIỆT NAM) =================
setInterval(async () => {
  try {
    const nowVN = new Date(new Date().toLocaleString('en-US', { timeZone: 'Asia/Ho_Chi_Minh' }));
    const hh = String(nowVN.getHours()).padStart(2, '0');
    const mm = String(nowVN.getMinutes()).padStart(2, '0');
    const currentTime = `${hh}:${mm}`;
    const todayStr = `${nowVN.getFullYear()}-${String(nowVN.getMonth() + 1).padStart(2, '0')}-${String(nowVN.getDate()).padStart(2, '0')}`;

    const { rows } = await pool.query(
      `SELECT * FROM schedules WHERE enabled = true AND schedule_time = $1 AND (last_triggered_date IS NULL OR last_triggered_date != $2)`,
      [currentTime, todayStr]
    );

    for (const sch of rows) {
      await pool.query('UPDATE device_states SET state = $1, updated_at = NOW() WHERE relay_id = $2', [
        sch.action,
        sch.relay_id,
      ]);
      await pool.query('UPDATE schedules SET last_triggered_date = $1 WHERE id = $2', [todayStr, sch.id]);

      const devRes = await pool.query('SELECT relay_name FROM device_states WHERE relay_id = $1', [sch.relay_id]);
      const devName = devRes.rows[0]?.relay_name || `Kênh ${sch.relay_id}`;
      await pool.query('INSERT INTO action_logs (username, action_desc) VALUES ($1, $2)', [
        'SCHEDULER',
        `Hẹn giờ (${currentTime}) -> ${sch.action ? 'BẬT' : 'TẮT'} ${devName}`,
      ]);
    }
  } catch (err) {
    console.error('Lỗi bộ đếm hẹn giờ:', err.message);
  }
}, 20000);

// Middleware xác thực JWT
function authMiddleware(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).json({ error: 'Chưa đăng nhập' });
  const token = authHeader.split(' ')[1];
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Phiên đăng nhập hết hạn' });
  }
}

app.get('/healthz', (req, res) => res.send('ok'));

// ================= API ĐĂNG NHẬP & QUẢN LÝ USER =================
app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  try {
    const { rows } = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
    if (rows.length === 0) return res.status(401).json({ error: 'Sai tên đăng nhập hoặc mật khẩu' });

    const user = rows[0];
    const valid = await bcrypt.compare(password, user.password_hash);
    if (!valid) return res.status(401).json({ error: 'Sai tên đăng nhập hoặc mật khẩu' });

    const payload = {
      id: user.id,
      username: user.username,
      full_name: user.full_name,
      role: user.role,
      can_relay_1: user.can_relay_1,
      can_relay_2: user.can_relay_2,
    };
    const token = jwt.sign(payload, JWT_SECRET, { expiresIn: '24h' });
    res.json({ token, user: payload });
  } catch {
    res.status(500).json({ error: 'Lỗi máy chủ' });
  }
});

app.get('/api/me', authMiddleware, async (req, res) => {
  const { rows } = await pool.query(
    'SELECT id, username, full_name, role, can_relay_1, can_relay_2 FROM users WHERE id = $1',
    [req.user.id]
  );
  res.json(rows[0]);
});

app.get('/api/users', authMiddleware, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Không có quyền Admin' });
  const { rows } = await pool.query(
    'SELECT id, username, full_name, role, can_relay_1, can_relay_2, created_at FROM users ORDER BY id ASC'
  );
  res.json(rows);
});

app.post('/api/users', authMiddleware, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Không có quyền Admin' });
  const { username, password, full_name, role, can_relay_1, can_relay_2 } = req.body;
  try {
    const hash = await bcrypt.hash(password, 10);
    const { rows } = await pool.query(
      `INSERT INTO users (username, password_hash, full_name, role, can_relay_1, can_relay_2)
       VALUES ($1, $2, $3, $4, $5, $6) RETURNING id, username, full_name, role, can_relay_1, can_relay_2`,
      [username, hash, full_name, role, !!can_relay_1, !!can_relay_2]
    );
    await pool.query('INSERT INTO action_logs (username, action_desc) VALUES ($1, $2)', [
      req.user.username,
      `Tạo tài khoản "${username}" (${role})`,
    ]);
    res.status(201).json(rows[0]);
  } catch {
    res.status(400).json({ error: 'Tên đăng nhập đã tồn tại hoặc dữ liệu không hợp lệ' });
  }
});

app.put('/api/users/:id/permissions', authMiddleware, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Không có quyền Admin' });
  const { role, can_relay_1, can_relay_2 } = req.body;
  const userId = parseInt(req.params.id, 10);
  const { rows } = await pool.query(
    `UPDATE users SET role = $1, can_relay_1 = $2, can_relay_2 = $3 WHERE id = $4
     RETURNING id, username, full_name, role, can_relay_1, can_relay_2`,
    [role, !!can_relay_1, !!can_relay_2, userId]
  );
  res.json(rows[0]);
});

app.delete('/api/users/:id', authMiddleware, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Không có quyền Admin' });
  const userId = parseInt(req.params.id, 10);
  if (userId === req.user.id) return res.status(400).json({ error: 'Không thể tự xóa tài khoản Admin đang đăng nhập' });
  await pool.query('DELETE FROM users WHERE id = $1', [userId]);
  res.json({ success: true });
});

// ================= API CẢM BIẾN =================
app.post('/api/sensors', async (req, res) => {
  try {
    const { device_id = 'esp32_gateway_01', temperature, humidity, gas_value } = req.body;
    const { rows } = await pool.query(
      'INSERT INTO sensor_logs (device_id, temperature, humidity, gas_value) VALUES ($1, $2, $3, $4) RETURNING *',
      [device_id, temperature, humidity, gas_value]
    );

    const cfgRes = await pool.query('SELECT * FROM system_settings WHERE id = 1');
    const cfg = cfgRes.rows[0];
    if (cfg && cfg.auto_ventilation && gas_value >= cfg.gas_threshold) {
      const relay2 = await pool.query('SELECT state, relay_name FROM device_states WHERE relay_id = 2');
      if (relay2.rows[0] && !relay2.rows[0].state) {
        const devName = relay2.rows[0].relay_name || 'Thiết bị Kênh 2';
        await pool.query('UPDATE device_states SET state = true, updated_at = NOW() WHERE relay_id = 2');
        await pool.query('INSERT INTO action_logs (username, action_desc) VALUES ($1, $2)', [
          'SYSTEM_AUTO',
          `Cảnh báo Gas (${gas_value} ppm >= ${cfg.gas_threshold} ppm) -> Tự động BẬT ${devName}`,
        ]);
      }
    }

    await pool.query("DELETE FROM sensor_logs WHERE created_at < NOW() - INTERVAL '30 days'");
    res.status(201).json(rows[0]);
  } catch {
    res.status(500).json({ error: 'Lỗi ghi dữ liệu cảm biến' });
  }
});

app.get('/api/sensors/latest', authMiddleware, async (req, res) => {
  const { rows } = await pool.query('SELECT * FROM sensor_logs ORDER BY created_at DESC LIMIT 25');
  res.json(rows.reverse());
});

app.get('/api/sensors/export', authMiddleware, async (req, res) => {
  const { rows } = await pool.query(
    'SELECT id, device_id, temperature, humidity, gas_value, created_at FROM sensor_logs ORDER BY created_at DESC LIMIT 1000'
  );
  let csv = 'ID,ThietBi,NhietDo(C),DoAm(%),KhiGas(ppm),ThoiGian\n';
  rows.forEach((r) => {
    csv += `${r.id},${r.device_id},${r.temperature},${r.humidity},${r.gas_value},${new Date(r.created_at).toISOString()}\n`;
  });
  res.setHeader('Content-Type', 'text/csv; charset=utf-8');
  res.setHeader('Content-Disposition', 'attachment; filename="baocao_smarthome.csv"');
  res.send('\uFEFF' + csv);
});

// ================= API RELAY =================
app.get('/api/relays', async (req, res) => {
  const { rows } = await pool.query('SELECT * FROM device_states ORDER BY relay_id ASC');
  res.json(rows);
});

app.put('/api/relays/:id/name', authMiddleware, async (req, res) => {
  const relayId = parseInt(req.params.id, 10);
  const { relay_name } = req.body;
  if (!relay_name || !relay_name.trim()) return res.status(400).json({ error: 'Tên thiết bị không được để trống' });
  const cleanName = relay_name.trim();
  const { rows } = await pool.query(
    'UPDATE device_states SET relay_name = $1, updated_at = NOW() WHERE relay_id = $2 RETURNING *',
    [cleanName, relayId]
  );
  await pool.query('INSERT INTO action_logs (username, action_desc) VALUES ($1, $2)', [
    req.user.username,
    `Đổi tên Kênh ${relayId} thành "${cleanName}"`,
  ]);
  res.json(rows[0]);
});

app.post('/api/relays/:id', authMiddleware, async (req, res) => {
  const relayId = parseInt(req.params.id, 10);
  const { state } = req.body;

  const userRes = await pool.query('SELECT * FROM users WHERE id = $1', [req.user.id]);
  const currentUser = userRes.rows[0];

  if (currentUser.role === 'viewer') return res.status(403).json({ error: 'Tài khoản Chỉ xem không được phép điều khiển!' });
  if (relayId === 1 && !currentUser.can_relay_1 && currentUser.role !== 'admin')
    return res.status(403).json({ error: 'Chưa được cấp quyền điều khiển Kênh 1!' });
  if (relayId === 2 && !currentUser.can_relay_2 && currentUser.role !== 'admin')
    return res.status(403).json({ error: 'Chưa được cấp quyền điều khiển Kênh 2!' });

  const { rows } = await pool.query(
    'UPDATE device_states SET state = $1, updated_at = NOW() WHERE relay_id = $2 RETURNING *',
    [state, relayId]
  );

  const deviceName = rows[0]?.relay_name || `Thiết bị Kênh ${relayId}`;
  await pool.query('INSERT INTO action_logs (username, action_desc) VALUES ($1, $2)', [
    currentUser.username,
    `${state ? 'BẬT' : 'TẮT'} ${deviceName} (Kênh ${relayId})`,
  ]);

  res.json(rows[0]);
});

// ================= API HẸN GIỜ (SCHEDULES) =================
app.get('/api/schedules', authMiddleware, async (req, res) => {
  const { rows } = await pool.query('SELECT * FROM schedules ORDER BY schedule_time ASC');
  res.json(rows);
});

app.post('/api/schedules', authMiddleware, async (req, res) => {
  if (req.user.role === 'viewer') return res.status(403).json({ error: 'Tài khoản Chỉ xem không thể tạo lịch hẹn giờ' });
  const { relay_id, action, schedule_time } = req.body;
  if (!relay_id || !schedule_time) return res.status(400).json({ error: 'Thiếu thông tin hẹn giờ' });

  const { rows } = await pool.query(
    `INSERT INTO schedules (relay_id, action, schedule_time, enabled) VALUES ($1, $2, $3, true) RETURNING *`,
    [parseInt(relay_id, 10), !!action, schedule_time]
  );
  await pool.query('INSERT INTO action_logs (username, action_desc) VALUES ($1, $2)', [
    req.user.username,
    `Thêm lịch hẹn: ${action ? 'BẬT' : 'TẮT'} Kênh ${relay_id} lúc ${schedule_time}`,
  ]);
  res.status(201).json(rows[0]);
});

app.put('/api/schedules/:id/toggle', authMiddleware, async (req, res) => {
  if (req.user.role === 'viewer') return res.status(403).json({ error: 'Không có quyền thao tác' });
  const { enabled } = req.body;
  const { rows } = await pool.query('UPDATE schedules SET enabled = $1 WHERE id = $2 RETURNING *', [
    !!enabled,
    parseInt(req.params.id, 10),
  ]);
  res.json(rows[0]);
});

app.delete('/api/schedules/:id', authMiddleware, async (req, res) => {
  if (req.user.role === 'viewer') return res.status(403).json({ error: 'Không có quyền thao tác' });
  await pool.query('DELETE FROM schedules WHERE id = $1', [parseInt(req.params.id, 10)]);
  res.json({ success: true });
});

// ================= API PHẦN CỨNG: SD CARD, TỐC ĐỘ MẠNG, ETHERNET/WIFI =================
// ESP32 gửi trạng thái phần cứng định kỳ lên endpoint này
app.post('/api/device/status', async (req, res) => {
  try {
    const { connection_mode, net_speed_mbps, rssi, ip_address, sd_total_mb, sd_used_mb } = req.body;
    const { rows } = await pool.query(
      `UPDATE gateway_status
       SET connection_mode = COALESCE($1, connection_mode),
           net_speed_mbps = COALESCE($2, net_speed_mbps),
           rssi = COALESCE($3, rssi),
           ip_address = COALESCE($4, ip_address),
           sd_total_mb = COALESCE($5, sd_total_mb),
           sd_used_mb = COALESCE($6, sd_used_mb),
           last_seen = NOW()
       WHERE id = 1 RETURNING *`,
      [connection_mode, net_speed_mbps, rssi, ip_address, sd_total_mb, sd_used_mb]
    );
    res.json(rows[0]);
  } catch {
    res.status(500).json({ error: 'Lỗi cập nhật trạng thái phần cứng' });
  }
});

// Web lấy trạng thái phần cứng
app.get('/api/device/status', authMiddleware, async (req, res) => {
  const { rows } = await pool.query('SELECT * FROM gateway_status WHERE id = 1');
  res.json(rows[0]);
});

// Web chọn chế độ ưu tiên kết nối (ethernet / wifi / auto)
app.put('/api/device/mode', authMiddleware, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Chỉ Admin mới được đổi chế độ mạng' });
  const { preferred_mode } = req.body;
  if (!['auto', 'ethernet', 'wifi'].includes(preferred_mode)) {
    return res.status(400).json({ error: 'Chế độ mạng không hợp lệ' });
  }
  const { rows } = await pool.query('UPDATE gateway_status SET preferred_mode = $1 WHERE id = 1 RETURNING *', [
    preferred_mode,
  ]);
  await pool.query('INSERT INTO action_logs (username, action_desc) VALUES ($1, $2)', [
    req.user.username,
    `Chuyển ưu tiên kết nối sang: ${preferred_mode.toUpperCase()}`,
  ]);
  res.json(rows[0]);
});

// ================= API CÀI ĐẶT WI-FI TỪ XA CHO ESP32 =================
app.get('/api/device/wifi', authMiddleware, async (req, res) => {
  const { rows } = await pool.query('SELECT ssid, pending_update, updated_at FROM wifi_config WHERE id = 1');
  res.json(rows[0]);
});

app.post('/api/device/wifi', authMiddleware, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Chỉ Admin mới được đổi Wi-Fi ESP32' });
  const { ssid, password } = req.body;
  if (!ssid || !ssid.trim()) return res.status(400).json({ error: 'Tên Wi-Fi (SSID) không được để trống' });

  const { rows } = await pool.query(
    `UPDATE wifi_config SET ssid = $1, password = $2, pending_update = true, updated_at = NOW() WHERE id = 1 RETURNING ssid, pending_update, updated_at`,
    [ssid.trim(), password || '']
  );
  await pool.query('INSERT INTO action_logs (username, action_desc) VALUES ($1, $2)', [
    req.user.username,
    `Cập nhật cấu hình Wi-Fi mới cho ESP32: "${ssid.trim()}"`,
  ]);
  res.json(rows[0]);
});

// Endpoint tổng hợp cho ESP32 kéo cấu hình Wi-Fi + Chế độ mạng (khi mạch mới về)
app.get('/api/esp32/config', async (req, res) => {
  const wifiRes = await pool.query('SELECT ssid, password, pending_update FROM wifi_config WHERE id = 1');
  const netRes = await pool.query('SELECT preferred_mode FROM gateway_status WHERE id = 1');
  res.json({
    preferred_mode: netRes.rows[0]?.preferred_mode || 'auto',
    wifi: wifiRes.rows[0] || { ssid: '', password: '', pending_update: false },
  });
});

// ESP32 gọi endpoint này sau khi đã lưu Wi-Fi mới thành công vào NVS
app.post('/api/esp32/wifi-ack', async (req, res) => {
  await pool.query('UPDATE wifi_config SET pending_update = false WHERE id = 1');
  res.json({ success: true });
});

// ================= API NGƯỠNG & NHẬT KÝ =================
app.get('/api/settings', authMiddleware, async (req, res) => {
  const { rows } = await pool.query('SELECT * FROM system_settings WHERE id = 1');
  res.json(rows[0]);
});

app.post('/api/settings', authMiddleware, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Chỉ Admin mới được đổi ngưỡng hệ thống' });
  const { gas_threshold, temp_threshold, auto_ventilation } = req.body;
  const { rows } = await pool.query(
    'UPDATE system_settings SET gas_threshold = $1, temp_threshold = $2, auto_ventilation = $3, updated_at = NOW() WHERE id = 1 RETURNING *',
    [gas_threshold, temp_threshold, auto_ventilation]
  );
  await pool.query('INSERT INTO action_logs (username, action_desc) VALUES ($1, $2)', [
    req.user.username,
    `Cập nhật ngưỡng: Gas=${gas_threshold}ppm, Nhiệt=${temp_threshold}°C`,
  ]);
  res.json(rows[0]);
});

app.get('/api/logs', authMiddleware, async (req, res) => {
  const { rows } = await pool.query('SELECT * FROM action_logs ORDER BY created_at DESC LIMIT 20');
  res.json(rows);
});

const port = process.env.PORT || 3000;
app.listen(port, '0.0.0.0', () => {
  console.log(`Smart Home Gateway Dashboard đang chạy tại cổng ${port}`);
});