require('dotenv').config();
const express = require('express');
const path = require('path');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }, // Bắt buộc cho Supabase
  max: 5, // Giới hạn kết nối cho gói Free
});

const JWT_SECRET = process.env.JWT_SECRET || 'doan2_smart_home_gateway_secret';
const app = express();
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// Tự động tạo tài khoản Admin mặc định (admin / 123456) nếu chưa có
async function initDefaultAdmin() {
  try {
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
  } catch (err) {
    console.error('Lỗi khởi tạo Admin:', err.message);
  }
}
initDefaultAdmin();

// Middleware xác thực JWT từ trình duyệt
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

// Endpoint giữ server không ngủ cho UptimeRobot
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
  } catch (err) {
    res.status(500).json({ error: 'Lỗi máy chủ' });
  }
});

// Lấy thông tin quyền hiện tại của user
app.get('/api/me', authMiddleware, async (req, res) => {
  const { rows } = await pool.query(
    'SELECT id, username, full_name, role, can_relay_1, can_relay_2 FROM users WHERE id = $1',
    [req.user.id]
  );
  res.json(rows[0]);
});

// Danh sách người dùng (Chỉ Admin)
app.get('/api/users', authMiddleware, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Không có quyền Admin' });
  const { rows } = await pool.query(
    'SELECT id, username, full_name, role, can_relay_1, can_relay_2, created_at FROM users ORDER BY id ASC'
  );
  res.json(rows);
});

// Tạo tài khoản người dùng mới và cấp quyền (Chỉ Admin)
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
      `Tạo tài khoản "${username}" (Vai trò: ${role})`,
    ]);
    res.status(201).json(rows[0]);
  } catch (err) {
    res.status(400).json({ error: 'Tên đăng nhập đã tồn tại hoặc dữ liệu không hợp lệ' });
  }
});

// Cập nhật quyền cho từng người dùng (Chỉ Admin)
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

// Xóa người dùng (Chỉ Admin, không được tự xóa chính mình)
app.delete('/api/users/:id', authMiddleware, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Không có quyền Admin' });
  const userId = parseInt(req.params.id, 10);
  if (userId === req.user.id) return res.status(400).json({ error: 'Không thể tự xóa tài khoản Admin đang đăng nhập' });
  await pool.query('DELETE FROM users WHERE id = $1', [userId]);
  res.json({ success: true });
});

// ================= API CẢM BIẾN & TỰ ĐỘNG HÓA (ESP32 + WEB) =================
app.post('/api/sensors', async (req, res) => {
  try {
    const { device_id = 'esp32_gateway_01', temperature, humidity, gas_value } = req.body;
    const { rows } = await pool.query(
      'INSERT INTO sensor_logs (device_id, temperature, humidity, gas_value) VALUES ($1, $2, $3, $4) RETURNING *',
      [device_id, temperature, humidity, gas_value]
    );

    // Kiểm tra quy tắc tự động hóa (Auto Ventilation)
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

    // Dọn dẹp log cũ hơn 30 ngày để tối ưu 500 MB của Supabase Free
    await pool.query("DELETE FROM sensor_logs WHERE created_at < NOW() - INTERVAL '30 days'");
    res.status(201).json(rows[0]);
  } catch (err) {
    res.status(500).json({ error: 'Lỗi ghi dữ liệu cảm biến' });
  }
});

app.get('/api/sensors/latest', authMiddleware, async (req, res) => {
  const { rows } = await pool.query('SELECT * FROM sensor_logs ORDER BY created_at DESC LIMIT 25');
  res.json(rows.reverse());
});

// Xuất báo cáo CSV lịch sử cảm biến
app.get('/api/sensors/export', authMiddleware, async (req, res) => {
  const { rows } = await pool.query('SELECT id, device_id, temperature, humidity, gas_value, created_at FROM sensor_logs ORDER BY created_at DESC LIMIT 1000');
  let csv = 'ID,ThietBi,NhietDo(C),DoAm(%),KhiGas(ppm),ThoiGian\n';
  rows.forEach(r => {
    csv += `${r.id},${r.device_id},${r.temperature},${r.humidity},${r.gas_value},${new Date(r.created_at).toISOString()}\n`;
  });
  res.setHeader('Content-Type', 'text/csv; charset=utf-8');
  res.setHeader('Content-Disposition', 'attachment; filename="baocao_smarthome.csv"');
  res.send('\uFEFF' + csv);
});

// ================= API ĐIỀU KHIỂN RELAY & ĐỔI TÊN THIẾT BỊ =================
// ESP32 gọi trực tiếp endpoint này để đồng bộ chân G27 và G14
app.get('/api/relays', async (req, res) => {
  const { rows } = await pool.query('SELECT * FROM device_states ORDER BY relay_id ASC');
  res.json(rows);
});

// Cập nhật tên thiết bị Relay vào database Supabase
app.put('/api/relays/:id/name', authMiddleware, async (req, res) => {
  const relayId = parseInt(req.params.id, 10);
  const { relay_name } = req.body;
  if (!relay_name || !relay_name.trim()) {
    return res.status(400).json({ error: 'Tên thiết bị không được để trống' });
  }
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

// Web Dashboard gọi điều khiển Relay (Kiểm tra quyền từng kênh)
app.post('/api/relays/:id', authMiddleware, async (req, res) => {
  const relayId = parseInt(req.params.id, 10);
  const { state } = req.body;

  const userRes = await pool.query('SELECT * FROM users WHERE id = $1', [req.user.id]);
  const currentUser = userRes.rows[0];

  if (currentUser.role === 'viewer') {
    return res.status(403).json({ error: 'Tài khoản Chỉ xem (Viewer) không được phép điều khiển thiết bị!' });
  }
  if (relayId === 1 && !currentUser.can_relay_1 && currentUser.role !== 'admin') {
    return res.status(403).json({ error: 'Bạn chưa được cấp quyền điều khiển Kênh 1!' });
  }
  if (relayId === 2 && !currentUser.can_relay_2 && currentUser.role !== 'admin') {
    return res.status(403).json({ error: 'Bạn chưa được cấp quyền điều khiển Kênh 2!' });
  }

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

// Lấy & Cập nhật ngưỡng cảnh báo + Tự động hóa
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
    `Cập nhật ngưỡng: Gas=${gas_threshold}ppm, Nhiệt=${temp_threshold}°C, AutoKênh2=${auto_ventilation ? 'Bật' : 'Tắt'}`,
  ]);
  res.json(rows[0]);
});

// Lấy nhật ký thao tác gần nhất
app.get('/api/logs', authMiddleware, async (req, res) => {
  const { rows } = await pool.query('SELECT * FROM action_logs ORDER BY created_at DESC LIMIT 15');
  res.json(rows);
});

const port = process.env.PORT || 3000;
app.listen(port, '0.0.0.0', () => {
  console.log(`Smart Home Dashboard đang chạy tại cổng ${port}`);
});