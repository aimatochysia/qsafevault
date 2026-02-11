import 'package:hive/hive.dart';

/// Service for managing the user-configurable API endpoint.
///
/// The default endpoint is the public relay at qsafevault-server.vercel.app.
/// Users can change this to point to their own self-hosted server,
/// and can set their own default.
class ApiEndpointService {
  static const String _boxName = 'api_endpoint_settings';
  static const String _endpointKey = 'api_endpoint';
  static const String _customDefaultKey = 'custom_default_endpoint';

  /// Default public relay endpoint
  static const String defaultEndpoint = 'https://qsafevault-server.vercel.app';

  static ApiEndpointService? _instance;
  Box? _box;

  ApiEndpointService._();

  static ApiEndpointService get instance {
    _instance ??= ApiEndpointService._();
    return _instance!;
  }

  /// Initialize the service (opens the Hive box)
  Future<void> init() async {
    if (_box != null && _box!.isOpen) return;
    _box = await Hive.openBox(_boxName);
  }

  /// Get the current API endpoint
  String get endpoint {
    if (_box == null || !_box!.isOpen) return defaultEndpoint;
    return _box!.get(_endpointKey, defaultValue: _userDefault) as String;
  }

  /// Get the user's custom default (falls back to the built-in default)
  String get _userDefault {
    if (_box == null || !_box!.isOpen) return defaultEndpoint;
    return _box!.get(_customDefaultKey, defaultValue: defaultEndpoint) as String;
  }

  /// Get the user's custom default endpoint (public accessor)
  String get customDefault {
    return _userDefault;
  }

  /// Set the current API endpoint
  Future<void> setEndpoint(String url) async {
    await init();
    final trimmed = url.trim().replaceAll(RegExp(r'/+$'), '');
    if (trimmed.isEmpty) {
      await _box!.put(_endpointKey, _userDefault);
    } else {
      await _box!.put(_endpointKey, trimmed);
    }
  }

  /// Set the user's custom default endpoint
  Future<void> setCustomDefault(String url) async {
    await init();
    final trimmed = url.trim().replaceAll(RegExp(r'/+$'), '');
    if (trimmed.isEmpty) {
      await _box!.delete(_customDefaultKey);
    } else {
      await _box!.put(_customDefaultKey, trimmed);
    }
  }

  /// Reset the endpoint to the user's custom default (or built-in default)
  Future<void> resetToDefault() async {
    await init();
    await _box!.delete(_endpointKey);
  }

  /// Reset everything to the built-in default
  Future<void> resetAll() async {
    await init();
    await _box!.delete(_endpointKey);
    await _box!.delete(_customDefaultKey);
  }
}
