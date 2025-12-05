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

  Future<void> _waitForAck(String inviteCode, String pwd) async {
    final hash = _passwordHash(pwd);
    final cfg = SyncConfig.defaults();
    final baseUrl = cfg.baseUrl.replaceAll(RegExp(r'/+$'), '');
    final url = Uri.parse('$baseUrl/api/relay');
    int tries = 0;
    while (mounted && tries < 60) {
      await Future.delayed(const Duration(seconds: 1));
      try {
        final resp = await http.post(url,
          body: jsonEncode({'action': 'ack-status', 'pin': inviteCode, 'passwordHash': hash}),
          headers: {'Content-Type': 'application/json'}).timeout(cfg.httpTimeout);
        if (resp.statusCode == 200 && jsonDecode(resp.body)['acknowledged'] == true) {
          if (!mounted) return;
          setState(() { _status = 'Acknowledged – waiting for return transfer…'; });
          return;
        }
      } catch (_) {}
      
      if (tries > 10) {
        try {
          final receiveResp = await http.post(url,
            body: jsonEncode({'action': 'receive', 'pin': inviteCode, 'passwordHash': hash}),
            headers: {'Content-Type': 'application/json'}).timeout(cfg.httpTimeout);
          if (receiveResp.statusCode == 200) {
            final body = jsonDecode(receiveResp.body);
            if (body['status'] == 'done') {
              if (!mounted) return;
              setState(() { _status = 'Transfer complete – waiting for return transfer…'; });
              return;
            }
          }
        } catch (_) {}
      }
      
      tries++;
      if (!mounted) return;
      setState(() { _status = 'Waiting for other device to acknowledge…'; });
    }
    setState(() { _error = 'Timeout waiting for other device.'; });
  }

  Future<void> _sendAck(String inviteCode, String pwd) async {
    final hash = _passwordHash(pwd);
    final cfg = SyncConfig.defaults();
    final baseUrl = cfg.baseUrl.replaceAll(RegExp(r'/+$'), '');
    final url = Uri.parse('$baseUrl/api/relay');
    try {
      await http.post(url, body: jsonEncode({'action': 'ack', 'pin': inviteCode, 'passwordHash': hash}), headers: {'Content-Type': 'application/json'}).timeout(cfg.httpTimeout);
    } catch (_) {}
  }
  final SyncService _sync = SyncService();

  RelayRole _role = RelayRole.sender;
  String _status = 'Idle';
  String? _error;

  final _inviteCodeCtl = TextEditingController();
  final _pwdCtl = TextEditingController();

  bool _busy = false;
  int _sent = 0;
  int _received = 0;

  StreamSubscription<SyncEvent>? _sub;

  bool _senderSessionStarted = false;
  String? _generatedInviteCode;

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
    _inviteCodeCtl.dispose();
    _pwdCtl.dispose();
    super.dispose();
  }

  /// Generate 8-character alphanumeric invite code
  String _genInviteCode() {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    final random = Random.secure();
    return List.generate(8, (_) => chars[random.nextInt(chars.length)]).join();
  }

  Future<void> _startSend() async {
    if (_busy) return;
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
      _generatedInviteCode = null;
    });
    try {
      final genInviteCode = _genInviteCode();
      final session = await _sync.createRelaySession(password: pwd, inviteCodeOverride: genInviteCode);
      _inviteCodeCtl.text = session.inviteCode;
      setState(() {
        _generatedInviteCode = session.inviteCode;
        _senderSessionStarted = true;
      });
      await _sync.sendVaultRelay(
        session: session,
        transferPassword: pwd,
        getVaultJson: () async => widget.currentVaultJson,
      );
      if (!mounted) return;
      setState(() {
        _status = 'Upload complete. Waiting for other device to receive…';
        _busy = true;
      });
      await _waitForAck(session.inviteCode, pwd);
      if (!mounted) return;
      setState(() {
        _role = RelayRole.receiver;
        _busy = false;
        _error = null;
      });
      await _startReceive(auto: true, inviteCode: session.inviteCode, pwd: pwd);
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

  Future<void> _startSendWithInviteCode(String inviteCode, String pwd) async {
    if (_busy) return;
    if (pwd.length < 6) {
      setState(() => _error = 'Transfer password too short');
      return;
    }
    setState(() {
      _busy = true;
      _status = 'Sending back…';
      _error = null;
      _sent = 0;
    });
    try {
      final session = await _sync.createRelaySession(password: pwd, inviteCodeOverride: inviteCode);
      await _sync.sendVaultRelay(
        session: session,
        transferPassword: pwd,
        getVaultJson: () async => widget.currentVaultJson,
      );
      if (!mounted) return;
      setState(() {
        _status = 'Return transfer complete. Waiting for acknowledgment…';
        _busy = true;
      });
      await _waitForAck(session.inviteCode, pwd);
      if (!mounted) return;
      await Future.delayed(const Duration(milliseconds: 300));
      if (!mounted) return;
      Navigator.of(context).pop();
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(content: Text('Vault synced bidirectionally (relay).')),
      );
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

  Future<void> _startReceive({bool auto = false, String? inviteCode, String? pwd}) async {
    if (_busy) return;
    final useInviteCode = inviteCode ?? _inviteCodeCtl.text.trim();
    final usePwd = pwd ?? _pwdCtl.text.trim();
    if (!_validInputs(useInviteCode, usePwd)) return;
    setState(() {
      _busy = true;
      _status = 'Waiting for chunks…';
      _error = null;
      _received = 0;
    });
    try {
      final session = await _sync.createRelaySession(password: usePwd, inviteCodeOverride: useInviteCode);
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
      await _sendAck(session.inviteCode, usePwd);
      if (!mounted) return;
      widget.onReceiveData(decrypted);
      if (auto) {
        await Future.delayed(const Duration(milliseconds: 300));
        if (!mounted) return;
        Navigator.of(context).pop();
        ScaffoldMessenger.of(context).showSnackBar(
          const SnackBar(content: Text('Vault synced bidirectionally (relay).')),
        );
      } else {
        setState(() {
          _role = RelayRole.sender;
          _busy = false;
          _error = null;
          _senderSessionStarted = false;
        });
        await Future.delayed(const Duration(seconds: 1));
        if (!mounted) return;
        await _startSendWithInviteCode(useInviteCode, usePwd);
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

  bool _validInputs(String inviteCode, String pwd) {
    // Validate 8-character alphanumeric invite code
    if (!RegExp(r'^[A-Za-z0-9]{8}$').hasMatch(inviteCode)) {
      setState(() => _error = 'Invite code must be 8 alphanumeric characters');
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
            if (_senderSessionStarted && _generatedInviteCode != null)
              Column(
                crossAxisAlignment: CrossAxisAlignment.stretch,
                children: [
                  Text(
                    'Code: $_generatedInviteCode',
                    style: const TextStyle(fontSize: 22, fontWeight: FontWeight.bold, letterSpacing: 2, fontFamily: 'monospace'),
                    textAlign: TextAlign.center,
                  ),
                  const SizedBox(height: 8),
                  const Text(
                    'Share this 8-character code with the receiver.',
                    style: TextStyle(fontSize: 13),
                    textAlign: TextAlign.center,
                  ),
                  const SizedBox(height: 8),
                ],
              ),
          ]
        else
          TextField(
            controller: _inviteCodeCtl,
            enabled: !_busy,
            keyboardType: TextInputType.text,
            textCapitalization: TextCapitalization.none,
            maxLength: 8,
            style: const TextStyle(fontFamily: 'monospace', letterSpacing: 2),
            decoration: const InputDecoration(
              labelText: '8-character invite code',
              counterText: '',
              border: OutlineInputBorder(),
              hintText: 'e.g., Ab3Xy9Zk',
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
          'Both devices must enter the SAME invite code + password within ~60s. '
          'Data is end‑to‑end encrypted; relay never sees plaintext.',
          style: TextStyle(fontSize: 11),
        ),
      ],
    );
  }
}
