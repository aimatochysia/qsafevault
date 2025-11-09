import 'package:flutter/material.dart';
import 'dart:async';
import 'dart:math';
import 'dart:convert';
import 'package:http/http.dart' as http;
import '/services/sync_service.dart';
import '/config/sync_config.dart';

enum RelayRole { sender, receiver }

class SyncDialog extends StatefulWidget {
  final Function(String vaultJson) onReceiveData;
  final String currentVaultJson;
  final RelayRole? initialRole;
  const SyncDialog({
    Key? key,
    required this.onReceiveData,
    required this.currentVaultJson,
    this.initialRole,
  }) : super(key: key);

  @override
  State<SyncDialog> createState() => _SyncDialogState();
}

class _SyncDialogState extends State<SyncDialog> {
  String _passwordHash(String pwd) {
    return base64Url.encode(utf8.encode(pwd));
  }

  Future<void> _waitForAck(String pin, String pwd) async {
    final hash = _passwordHash(pwd);
    final cfg = SyncConfig.defaults();
    final baseUrl = cfg.baseUrl.replaceAll(RegExp(r'/+$'), '');
    final url = Uri.parse('$baseUrl/api/relay');
    int tries = 0;
    while (mounted && tries < 60) {
      await Future.delayed(const Duration(seconds: 1));
      try {
        final resp = await http.post(url,
          body: jsonEncode({'action': 'ack-status', 'pin': pin, 'passwordHash': hash}),
          headers: {'Content-Type': 'application/json'}).timeout(cfg.httpTimeout);
        if (resp.statusCode == 200 && jsonDecode(resp.body)['acknowledged'] == true) return;
      } catch (_) {}
      tries++;
      if (!mounted) return;
      setState(() { _status = 'Waiting for other device to finish…'; });
    }
    setState(() { _error = 'Timeout waiting for other device.'; });
  }

  Future<void> _sendAck(String pin, String pwd) async {
    final hash = _passwordHash(pwd);
    final cfg = SyncConfig.defaults();
    final baseUrl = cfg.baseUrl.replaceAll(RegExp(r'/+$'), '');
    final url = Uri.parse('$baseUrl/api/relay');
    try {
      await http.post(url, body: jsonEncode({'action': 'ack', 'pin': pin, 'passwordHash': hash}), headers: {'Content-Type': 'application/json'}).timeout(cfg.httpTimeout);
    } catch (_) {}
  }
  final SyncService _sync = SyncService();

  RelayRole _role = RelayRole.sender;
  String _status = 'Idle';
  String? _error;

  final _pinCtl = TextEditingController();
  final _pwdCtl = TextEditingController();

  bool _busy = false;
  int _sent = 0;
  int _received = 0;

  StreamSubscription<SyncEvent>? _sub;

  bool _senderSessionStarted = false;
  String? _generatedPin;

  @override
  void initState() {
    super.initState();
    _role = widget.initialRole ?? RelayRole.sender;
    _init();
  }

  Future<void> _init() async {
    await _sync.init();
    _sub = _sync.events?.listen((e) {
      if (!mounted) return;
      if (e is DataSentEvent) {
        setState(() => _sent++);
      } else if (e is DataReceivedEvent) {
        setState(() => _received++);
      } else if (e is HandshakeCompleteEvent) {
      } else if (e is ErrorEvent) {
        setState(() {
          _error = e.message;
          _status = 'Error';
          _busy = false;
        });
      }
    });
  }

  @override
  void dispose() {
    _sub?.cancel();
    _sync.stop();
    _pinCtl.dispose();
    _pwdCtl.dispose();
    super.dispose();
  }

  String _genPin() {
    final n = Random.secure().nextInt(1000000);
    return n.toString().padLeft(6, '0');
  }

  Future<void> _startSend() async {
    final pwd = _pwdCtl.text.trim();
    if (pwd.length < 6) {
      setState(() => _error = 'Transfer password too short');
      return;
    }
    setState(() {
      _busy = true;
      _status = 'Encrypting & uploading…';
      _error = null;
      _sent = 0;
      _senderSessionStarted = false;
      _generatedPin = null;
    });
    try {
      final genPin = _genPin();
      final session = await _sync.createRelaySession(password: pwd, pinOverride: genPin);
      _pinCtl.text = session.pin;
      setState(() {
        _generatedPin = session.pin;
        _senderSessionStarted = true;
      });
      await _sync.sendVaultRelay(
        session: session,
        transferPassword: pwd,
        getVaultJson: () async => widget.currentVaultJson,
      );
      if (!mounted) return;
      setState(() {
        _status = 'Upload complete. Waiting for other device to finish…';
        _busy = true;
      });
      await _waitForAck(session.pin, pwd);
      if (!mounted) return;
      setState(() {
        _role = RelayRole.receiver;
        _busy = false;
        _error = null;
      });
      await _startReceive(auto: true, pin: session.pin, pwd: pwd);
    } catch (e) {
      if (!mounted) return;
      setState(() {
        _error = '$e';
        _status = 'Error';
      });
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  Future<void> _startReceive({bool auto = false, String? pin, String? pwd}) async {
    final usePin = pin ?? _pinCtl.text.trim();
    final usePwd = pwd ?? _pwdCtl.text.trim();
    if (!_validInputs(usePin, usePwd)) return;
    setState(() {
      _busy = true;
      _status = 'Waiting for chunks…';
      _error = null;
      _received = 0;
    });
    try {
      final session = await _sync.createRelaySession(password: usePwd, pinOverride: usePin);
      final decrypted = await _sync.receiveVaultRelay(
        session: session,
        transferPassword: usePwd,
      );
      if (!mounted) return;
      if (decrypted == null) {
        setState(() {
          _status = 'Expired or incomplete.';
          _busy = false;
        });
        return;
      }
      setState(() {
        _status = 'Finalizing…';
        _busy = true;
      });
      await _sendAck(session.pin, usePwd);
      if (!mounted) return;
      widget.onReceiveData(decrypted);
      if (auto) {
        setState(() {
          _role = RelayRole.sender;
          _busy = false;
          _error = null;
          _senderSessionStarted = false;
        });
        await Future.delayed(const Duration(milliseconds: 300));
        if (!mounted) return;
        _startSend();
      } else {
        await Future.delayed(const Duration(milliseconds: 300));
        if (!mounted) return;
        Navigator.of(context).pop();
        ScaffoldMessenger.of(context).showSnackBar(
          const SnackBar(content: Text('Vault synced (relay).')),
        );
      }
    } catch (e) {
      if (!mounted) return;
      setState(() {
        _error = '$e';
        _status = 'Error';
      });
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  bool _validInputs(String pin, String pwd) {
    if (!RegExp(r'^\d{6}$').hasMatch(pin)) {
      setState(() => _error = 'PIN must be 6 digits');
      return false;
    }
    if (pwd.length < 6) {
      setState(() => _error = 'Transfer password too short');
      return false;
    }
    return true;
  }

  @override
  Widget build(BuildContext context) {
    final size = MediaQuery.of(context).size;
    final dialogW = size.width * 0.85;
    final dialogH = min(size.height * 0.8, 440.0);

    return AlertDialog(
      content: SizedBox(
        width: dialogW,
        height: dialogH,
        child: SingleChildScrollView(
          child: ConstrainedBox(
            constraints: BoxConstraints(minHeight: dialogH),
            child: IntrinsicHeight(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.stretch,
                children: [
                  const Text('Device Sync (Relay)', style: TextStyle(fontSize: 18, fontWeight: FontWeight.bold)),
                  const SizedBox(height: 6),
                  Text('Status: $_status', style: const TextStyle(fontSize: 13)),
                  if (_error != null) ...[
                    const SizedBox(height: 4),
                    Text(_error!, style: const TextStyle(color: Colors.red, fontSize: 12)),
                  ],
                  const SizedBox(height: 8),
                  ToggleButtons(
                    isSelected: [_role == RelayRole.sender, _role == RelayRole.receiver],
                    onPressed: _busy ? null : (i) => setState(() => _role = i == 0 ? RelayRole.sender : RelayRole.receiver),
                    children: const [
                      Padding(padding: EdgeInsets.symmetric(horizontal: 12), child: Text('Send')),
                      Padding(padding: EdgeInsets.symmetric(horizontal: 12), child: Text('Receive')),
                    ],
                  ),
                  const SizedBox(height: 12),
                  _inputs(),
                  const Spacer(),
                  if (_role == RelayRole.sender)
                    Text('Sent chunks: $_sent', style: const TextStyle(fontSize: 12))
                  else
                    Text('Received chunks: $_received', style: const TextStyle(fontSize: 12)),
                  const SizedBox(height: 8),
                  Row(
                    children: [
                      Expanded(
                        child: OutlinedButton(
                          onPressed: _busy ? null : () => Navigator.of(context).pop(),
                          child: const Text('Close'),
                        ),
                      ),
                      const SizedBox(width: 8),
                      Expanded(
                        child: ElevatedButton(
                          onPressed: _busy
                              ? null
                              : () {
                                  if (_role == RelayRole.sender) {
                                    _startSend();
                                  } else {
                                    _startReceive();
                                  }
                                },
                          child: Text(_busy
                              ? (_role == RelayRole.sender ? 'Sending…' : 'Receiving…')
                              : (_role == RelayRole.sender ? 'Send' : 'Receive')),
                        ),
                      ),
                    ],
                  )
                ],
              ),
            ),
          ),
        ),
      ),
    );
  }

  Widget _inputs() {
    final isSender = _role == RelayRole.sender;
    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        if (isSender)
          ...[
            if (_senderSessionStarted && _generatedPin != null)
              Column(
                crossAxisAlignment: CrossAxisAlignment.stretch,
                children: [
                  Text(
                    'PIN: $_generatedPin',
                    style: const TextStyle(fontSize: 22, fontWeight: FontWeight.bold, letterSpacing: 2),
                    textAlign: TextAlign.center,
                  ),
                  const SizedBox(height: 8),
                  const Text(
                    'Share this PIN with the receiver.',
                    style: TextStyle(fontSize: 13),
                    textAlign: TextAlign.center,
                  ),
                  const SizedBox(height: 8),
                ],
              ),
          ]
        else
          TextField(
            controller: _pinCtl,
            enabled: !_busy,
            keyboardType: TextInputType.number,
            maxLength: 6,
            decoration: const InputDecoration(
              labelText: '6‑digit PIN',
              counterText: '',
              border: OutlineInputBorder(),
            ),
          ),
        TextField(
          controller: _pwdCtl,
          enabled: !_busy && !(isSender && _senderSessionStarted),
          obscureText: true,
          decoration: const InputDecoration(
            labelText: 'Transfer password',
            border: OutlineInputBorder(),
          ),
        ),
        const SizedBox(height: 8),
        const Text(
          'Both devices must enter the SAME PIN + password within ~60s. '
          'Data is end‑to‑end encrypted; relay never sees plaintext.',
          style: TextStyle(fontSize: 11),
        ),
      ],
    );
  }
}
