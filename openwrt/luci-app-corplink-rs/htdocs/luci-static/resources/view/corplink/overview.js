'use strict';
'require view';
'require rpc';
'require ui';
'require poll';

var status = rpc.declare({ object: 'luci.corplink', method: 'status', expect: {} });
var getConfig = rpc.declare({ object: 'luci.corplink', method: 'get_config', expect: {} });
var saveConfig = rpc.declare({ object: 'luci.corplink', method: 'save_config', params: ['config'], expect: {} });
var control = rpc.declare({ object: 'luci.corplink', method: 'control', params: ['action'], expect: {} });
var loginBegin = rpc.declare({ object: 'luci.corplink', method: 'login_begin', expect: {} });
var loginStatus = rpc.declare({ object: 'luci.corplink', method: 'login_status', expect: {} });
var loginSubmit = rpc.declare({ object: 'luci.corplink', method: 'login_submit', params: ['id', 'prompt_id', 'value'], expect: {} });
var loginCancel = rpc.declare({ object: 'luci.corplink', method: 'login_cancel', params: ['id'], expect: {} });
var getLogs = rpc.declare({ object: 'luci.corplink', method: 'logs', expect: {} });

function checked(result) {
	if (!result || result.ok !== true) throw new Error(result && result.error || '路由器没有返回有效结果');
	return result;
}

function button(label, fn, primary) {
	return E('button', { 'type': 'button', 'class': 'cbi-button ' + (primary ? 'cbi-button-action important' : 'cbi-button-neutral'), 'click': fn }, label);
}

var css = '.corplink .cp-cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:12px;margin:18px 0}' +
	'.corplink .cp-card{border:1px solid var(--border-color,#d8dee5);border-radius:8px;padding:16px;background:var(--background-color,#fff)}' +
	'.corplink .cp-card small{display:block;opacity:.7;margin-bottom:7px}.corplink .cp-card strong{font-size:16px;overflow-wrap:anywhere}' +
	'.corplink .cp-actions{display:flex;align-items:center;gap:8px;flex-wrap:wrap;margin:12px 0}' +
	'.corplink .cp-panel{border-top:1px solid var(--border-color,#d8dee5);padding-top:18px;margin-top:24px}' +
	'.corplink .cp-hint{opacity:.75;font-size:13px;line-height:1.7}.corplink .cp-ok{color:#24824b}.corplink .cp-warn{color:#a56514}' +
	'.corplink .cp-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:16px 24px;margin:16px 0}' +
	'.corplink .cp-field label{font-weight:600;display:block;margin-bottom:6px}.corplink .cp-field input,.corplink .cp-field select{width:100%;box-sizing:border-box}' +
	'.corplink .cp-login{max-width:850px;border-left:3px solid #4285b4;padding:4px 0 4px 16px;margin:14px 0}' +
	'.corplink .cp-login textarea{width:100%;box-sizing:border-box;font-family:monospace}.corplink .cp-login input{max-width:340px;width:100%}' +
	'.corplink .cp-log{max-height:320px;overflow:auto;white-space:pre-wrap;overflow-wrap:anywhere;font-size:12px;padding:12px;background:var(--background-color,#f6f8fa)}' +
	'.corplink .cp-device{font-family:monospace;font-size:13px}.corplink .cp-error{color:#c43c35;white-space:pre-wrap}';

return view.extend({
	handleSaveApply: null,
	handleSave: null,
	handleReset: null,

	load: function() {
		return Promise.all([status(), getConfig(), loginStatus(), getLogs()]).then(function(results) { return results.map(checked); });
	},

	run: function(fn) {
		var self = this;
		if (this.busy) return Promise.resolve();
		this.busy = true;
		this.updateButtons();
		return Promise.resolve().then(fn).then(checked).catch(function(e) {
			ui.addNotification(null, E('p', {}, e.message), 'error');
		}).finally(function() {
			self.busy = false;
			return self.refresh();
		});
	},

	refresh: function() {
		var self = this;
		return Promise.all([status(), loginStatus()]).then(function(results) {
			self.state = checked(results[0]);
			self.auth = checked(results[1]).login;
			self.drawStatus();
			self.drawLogin();
			self.updateButtons();
			self.connectionError.textContent = '';
		}).catch(function(e) {
			self.connectionError.textContent = '状态刷新失败：' + e.message;
		});
	},

	updateButtons: function() {
		if (!this.buttons) return;
		var s = this.state || {}, active = s.login_active, busy = this.busy;
		this.buttons.start.disabled = busy || s.running || active || !s.logged_in;
		this.buttons.stop.disabled = busy || !s.running;
		this.buttons.restart.disabled = busy || !s.running || active;
		this.buttons.boot.disabled = busy;
		this.buttons.boot.textContent = s.enabled ? '关闭开机自启' : '启用开机自启';
		this.buttons.login.disabled = busy || s.running || active || !s.configured;
		this.buttons.login.textContent = s.logged_in ? '重新登录' : '开始登录';
		this.buttons.save.disabled = busy || s.running || active;
	},

	drawStatus: function() {
		var s = this.state;
		domContent(this.cards, [
			card('代理服务', s.running ? '正在运行' : '已停止', s.running ? 'cp-ok' : ''),
			card('本机 SOCKS5', s.listen || '127.0.0.1:1188'),
			card('登录会话', s.logged_in ? '已保存' : '需要登录', s.logged_in ? 'cp-ok' : 'cp-warn'),
			card('开机自启', s.enabled ? '已开启' : '未开启')
		]);
		this.nodeLabel.textContent = '目标节点：' + (s.server || '自动选择') + ' · 纯代理模式，系统路由和 DNS 不变';
	},

	drawLogin: function() {
		var self = this, s = this.auth || { stage: 'idle' };
		var key = JSON.stringify([s.id, s.stage, s.prompt_id, s.message, s.url, this.state.logged_in]);
		if (key === this.loginKey) return;
		this.loginKey = key;
		var nodes = [];
		if (s.stage === 'idle') {
			nodes.push(E('p', {}, this.state.logged_in ? '已有登录会话，可直接启动代理，无需重复授权。' : '使用已在官方飞连客户端注册的设备信息登录。'));
		} else if (s.stage === 'done') {
			nodes.push(E('p', { 'class': 'cp-ok' }, '登录成功。会话已保存，点击「启动」即可连接。'));
		} else if (['error', 'expired', 'cancelled'].indexOf(s.stage) !== -1) {
			nodes.push(E('p', { 'class': s.stage === 'cancelled' ? '' : 'cp-error' }, s.message || '请重新开始登录。'));
		} else {
			if (s.url && /^https:\/\//.test(s.url)) {
				nodes.push(E('p', {}, [E('a', { 'href': s.url, 'target': '_blank', 'rel': 'noopener noreferrer', 'class': 'cbi-button cbi-button-action' }, '打开飞连授权页面')]));
				nodes.push(E('p', { 'class': 'cp-hint' }, '授权完成后可取消「打开飞连」提示，复制地址栏中的完整回调地址，粘贴到下方。'));
			}
			if (s.message) nodes.push(E('p', { 'class': 'cp-error' }, s.message));
			if (s.stage === 'waiting') {
				var field = s.kind === 'callback'
					? E('textarea', { 'rows': 3, 'maxlength': 8192, 'autocomplete': 'off', 'spellcheck': 'false', 'aria-label': '完整回调地址', 'placeholder': '粘贴授权完成后的完整回调地址' })
					: E('input', { 'type': 'password', 'maxlength': 128, 'autocomplete': 'one-time-code', 'inputmode': 'numeric', 'aria-label': '验证码', 'placeholder': '输入本次验证码' });
				var submit = button(s.kind === 'callback' ? '提交授权结果' : '提交验证码', function() {
					var value = field.value.trim();
					if (!value) { field.focus(); return; }
					submit.disabled = true;
					self.run(function() { return loginSubmit(s.id, s.prompt_id, value); }).finally(function() { field.value = ''; submit.disabled = false; });
				}, true);
				field.addEventListener('keydown', function(e) { if (e.key === 'Enter' && (s.kind !== 'callback' || e.ctrlKey || e.metaKey)) { e.preventDefault(); submit.click(); } });
				nodes.push(E('p', {}, (s.prompt || '请完成当前验证').replace(/后按回车[：:]?$/, '').replace(/，然后按回车[：:]?$/, '')));
				nodes.push(field);
				nodes.push(E('div', { 'class': 'cp-actions' }, [submit, button('取消登录', function() { self.run(function() { return loginCancel(s.id); }); })]));
			} else {
				nodes.push(E('p', {}, s.stage === 'starting' ? '正在获取授权链接…' : '正在验证，请稍候…'));
				nodes.push(button('取消登录', function() { self.run(function() { return loginCancel(s.id); }); }));
			}
		}
		domContent(this.loginBox, nodes);
	},

	render: function(data) {
		var self = this;
		this.state = data[0]; this.auth = data[2].login; this.fields = {};
		this.cards = E('div', { 'class': 'cp-cards' });
		this.nodeLabel = E('p', { 'class': 'cp-hint' });
		this.connectionError = E('p', { 'class': 'cp-error', 'role': 'status' });
		this.loginBox = E('div', { 'class': 'cp-login', 'aria-live': 'polite' });
		this.logBox = E('pre', { 'class': 'cp-log', 'aria-label': '运行日志' }, (data[3].lines || []).join('\n') || '暂无运行日志');
		this.buttons = {
			start: button('启动', function() { self.run(function() { return control('start'); }); }, true),
			stop: button('停止', function() { self.run(function() { return control('stop'); }); }),
			restart: button('重启', function() { self.run(function() { return control('restart'); }); }),
			boot: button('启用开机自启', function() { self.run(function() { return control(self.state.enabled ? 'disable' : 'enable'); }); }),
			login: button('开始登录', function() { self.run(loginBegin); }, true),
			save: button('保存配置', function() {
				var config = {};
				for (var key in self.fields) config[key] = key === 'port' ? Number(self.fields[key].value) : self.fields[key].value.trim();
				self.run(function() { return saveConfig(config).then(function(r) {
					checked(r); ui.addNotification(null, E('p', {}, r.login_required ? '配置已保存，请完成登录。' : '配置已保存，可启动服务。'), 'info'); return r;
				}); });
			}, true)
		};
		var specs = [
			['company_name', '企业标识', '例如 bytedance；用于发现企业服务地址'],
			['server', '服务地址', 'HTTPS 根地址；留空时按企业标识自动发现'],
			['platform', '登录平台', '例如 bytedance_sso，保持与当前配置一致'],
			['username', '账号标识（可选）', '第三方 SSO 登录通常可留空'],
			['device_id', '设备 ID', '从官方客户端日志完整复制，注意区分 E / F'],
			['device_name', '设备名称', '使用官方客户端注册的设备名称，保持原样'],
			['vpn_server_name', 'VPN 节点（可选）', '例如 CN-IT-SH；留空时自动选择'],
			['port', 'SOCKS5 端口', '仅监听 127.0.0.1，不接管路由器流量'],
			['vpn_select_strategy', '自动选择方式', '仅在未指定节点时使用']
		];
		var fields = specs.map(function(spec) {
			var key = spec[0], input;
			if (key === 'vpn_select_strategy') {
				input = E('select', { 'id': 'cp-' + key }, [E('option', { 'value': 'default' }, '首个可用节点'), E('option', { 'value': 'latency' }, '最低延迟')]);
			} else {
				input = E('input', { 'id': 'cp-' + key, 'type': key === 'port' ? 'number' : 'text', 'autocomplete': 'off', 'spellcheck': 'false', 'maxlength': key === 'device_id' ? 64 : 512, 'class': key === 'device_id' ? 'cp-device' : '' });
				if (key === 'port') { input.min = 1024; input.max = 65535; }
			}
			input.value = data[1].config[key] == null ? '' : data[1].config[key];
			self.fields[key] = input;
			return E('div', { 'class': 'cp-field' }, [E('label', { 'for': 'cp-' + key }, spec[1]), input, E('small', { 'class': 'cp-hint' }, spec[2])]);
		});
		var root = E('div', { 'class': 'corplink' }, [
			E('style', {}, css), E('h2', {}, 'Corplink'), E('p', {}, '通过本机 SOCKS5 代理访问企业内网。'),
			this.cards, this.nodeLabel,
			E('div', { 'class': 'cp-actions' }, [this.buttons.start, this.buttons.stop, this.buttons.restart, this.buttons.boot]), this.connectionError,
			E('section', { 'class': 'cp-panel' }, [E('h3', {}, '飞连登录'), E('p', { 'class': 'cp-hint' }, '重新登录前先停止服务。授权最多保留 10 分钟，取消或失败时保留原有配置和会话。'), this.buttons.login, this.loginBox]),
			E('section', { 'class': 'cp-panel' }, [E('h3', {}, '代理配置'), E('p', { 'class': 'cp-hint' }, '修改配置前先停止服务。更换设备、企业或账号后需要重新登录。'), E('div', { 'class': 'cp-grid' }, fields), this.buttons.save]),
			E('section', { 'class': 'cp-panel' }, [E('h3', {}, '运行日志'), E('div', { 'class': 'cp-actions' }, [button('刷新日志', function() { getLogs().then(checked).then(function(r) { self.logBox.textContent = r.lines.join('\n') || '暂无运行日志'; }).catch(function(e) { ui.addNotification(null, E('p', {}, e.message), 'error'); }); })]), this.logBox])
		]);
		this.drawStatus(); this.drawLogin(); this.updateButtons();
		poll.add(function() { return self.refresh(); }, 3);
		return root;
	}
});

function domContent(node, children) {
	while (node.firstChild) node.removeChild(node.firstChild);
	children.forEach(function(child) { node.appendChild(child); });
}

function card(label, value, className) {
	return E('div', { 'class': 'cp-card' }, [E('small', {}, label), E('strong', { 'class': className || '' }, value)]);
}
