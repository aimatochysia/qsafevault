import 'dart:async';
import 'dart:convert';
import 'dart:typed_data';
import 'package:hive/hive.dart';
import 'package:path_provider/path_provider.dart';
import 'package:uuid/uuid.dart';
import 'package:cryptography/cryptography.dart';
import 'crypto_service.dart';

/// A simplified CRDT (Conflict-free Replicated Data Type) implementation
/// using Last-Writer-Wins (LWW) strategy with Lamport timestamps.
/// 
/// Each entry in the vault is treated as an independent LWW-Register.
/// Conflicts are resolved by preferring the entry with the higher timestamp.
/// If timestamps are equal, the entry with the lexicographically higher device ID wins.

/// Represents a single entry with CRDT metadata
class CrdtEntry {
  final String id;
  final String data; // JSON-encoded entry data
  final int timestamp; // Lamport timestamp
  final String deviceId; // Device that last modified this entry
  final bool deleted; // Tombstone flag for deleted entries

  CrdtEntry({
    required this.id,
    required this.data,
    required this.timestamp,
    required this.deviceId,
    this.deleted = false,
  });

  Map<String, dynamic> toJson() => {
    'id': id,
    'data': data,
    'timestamp': timestamp,
    'deviceId': deviceId,
    'deleted': deleted,
  };

  factory CrdtEntry.fromJson(Map<String, dynamic> json) => CrdtEntry(
    id: json['id'] as String,
    data: json['data'] as String,
    timestamp: json['timestamp'] as int,
    deviceId: json['deviceId'] as String,
    deleted: json['deleted'] as bool? ?? false,
  );

  /// Returns true if this entry should win over another entry with same ID
  bool winsOver(CrdtEntry other) {
    if (timestamp != other.timestamp) {
      return timestamp > other.timestamp;
    }
    // Tie-breaker: lexicographic comparison of device IDs
    return deviceId.compareTo(other.deviceId) > 0;
  }
}

/// CRDT Document containing all vault entries
class CrdtDocument {
  final Map<String, CrdtEntry> entries;
  int clock; // Local Lamport clock
  final String deviceId;

  CrdtDocument({
    Map<String, CrdtEntry>? entries,
    this.clock = 0,
    required this.deviceId,
  }) : entries = entries ?? {};

  /// Increment clock and return new timestamp
  int tick() {
    clock++;
    return clock;
  }

  /// Update clock to be at least the given value
  void updateClock(int receivedTime) {
    clock = clock > receivedTime ? clock : receivedTime;
  }

  /// Insert or update an entry
  CrdtEntry upsert(String id, String data) {
    final ts = tick();
    final entry = CrdtEntry(
      id: id,
      data: data,
      timestamp: ts,
      deviceId: deviceId,
    );
    entries[id] = entry;
    return entry;
  }

  /// Delete an entry (tombstone)
  CrdtEntry? delete(String id) {
    final existing = entries[id];
    if (existing == null) return null;
    
    final ts = tick();
    final tombstone = CrdtEntry(
      id: id,
      data: '',
      timestamp: ts,
      deviceId: deviceId,
      deleted: true,
    );
    entries[id] = tombstone;
    return tombstone;
  }

  /// Merge another document's entries into this one
  /// Returns list of entries that were updated
  List<CrdtEntry> merge(CrdtDocument other) {
    final updated = <CrdtEntry>[];
    
    // Update our clock
    updateClock(other.clock);
    
    for (final entry in other.entries.values) {
      final existing = entries[entry.id];
      if (existing == null || entry.winsOver(existing)) {
        entries[entry.id] = entry;
        updated.add(entry);
        updateClock(entry.timestamp);
      }
    }
    
    return updated;
  }

  /// Merge a single entry
  bool mergeEntry(CrdtEntry entry) {
    updateClock(entry.timestamp);
    final existing = entries[entry.id];
    if (existing == null || entry.winsOver(existing)) {
      entries[entry.id] = entry;
      return true;
    }
    return false;
  }

  /// Get all non-deleted entries
  List<CrdtEntry> get activeEntries =>
    entries.values.where((e) => !e.deleted).toList();

  /// Serialize for sync
  Map<String, dynamic> toJson() => {
    'entries': entries.map((k, v) => MapEntry(k, v.toJson())),
    'clock': clock,
    'deviceId': deviceId,
  };

  factory CrdtDocument.fromJson(Map<String, dynamic> json) {
    final entriesMap = (json['entries'] as Map<String, dynamic>? ?? {})
      .map((k, v) => MapEntry(k, CrdtEntry.fromJson(v as Map<String, dynamic>)));
    return CrdtDocument(
      entries: entriesMap,
      clock: json['clock'] as int? ?? 0,
      deviceId: json['deviceId'] as String,
    );
  }

  /// Create delta containing only entries changed since given clock value
  CrdtDocument delta({required int sinceTimestamp}) {
    final deltaEntries = <String, CrdtEntry>{};
    for (final entry in entries.entries) {
      if (entry.value.timestamp > sinceTimestamp) {
        deltaEntries[entry.key] = entry.value;
      }
    }
    return CrdtDocument(
      entries: deltaEntries,
      clock: clock,
      deviceId: deviceId,
    );
  }
}

/// Service for managing CRDT state with persistence and encryption
class CrdtService {
  static const String _boxName = 'qsv_crdt';
  static const String _docKey = 'document';
  static const String _deviceIdKey = 'device_id';
  
  final CryptoService _crypto;
  Box? _box;
  CrdtDocument? _document;
  String? _deviceId;
  
  final _changeController = StreamController<CrdtChangeEvent>.broadcast();
  
  CrdtService({CryptoService? crypto}) : _crypto = crypto ?? CryptoService();
  
  /// Stream of change events for UI updates
  Stream<CrdtChangeEvent> get changes => _changeController.stream;
  
  /// Current document (null if not initialized)
  CrdtDocument? get document => _document;
  
  /// Device ID
  String? get deviceId => _deviceId;
  
  /// Initialize the CRDT service
  Future<void> init() async {
    if (_box != null) return;
    
    final appDir = await getApplicationDocumentsDirectory();
    Hive.init('${appDir.path}/hive_crdt');
    
    _box = await Hive.openBox(_boxName);
    
    // Get or generate device ID
    _deviceId = _box!.get(_deviceIdKey) as String?;
    if (_deviceId == null) {
      _deviceId = const Uuid().v4();
      await _box!.put(_deviceIdKey, _deviceId);
    }
    
    // Load existing document or create new one
    final stored = _box!.get(_docKey) as String?;
    if (stored != null) {
      try {
        _document = CrdtDocument.fromJson(jsonDecode(stored) as Map<String, dynamic>);
      } catch (_) {
        _document = CrdtDocument(deviceId: _deviceId!);
      }
    } else {
      _document = CrdtDocument(deviceId: _deviceId!);
    }
  }
  
  /// Persist the current document
  Future<void> _persist() async {
    if (_box == null || _document == null) return;
    await _box!.put(_docKey, jsonEncode(_document!.toJson()));
  }
  
  /// Insert or update an entry
  Future<CrdtEntry> upsert(String id, Map<String, dynamic> data) async {
    if (_document == null) throw StateError('CRDT not initialized');
    
    final entry = _document!.upsert(id, jsonEncode(data));
    await _persist();
    _changeController.add(CrdtChangeEvent.updated(entry));
    return entry;
  }
  
  /// Delete an entry
  Future<CrdtEntry?> delete(String id) async {
    if (_document == null) throw StateError('CRDT not initialized');
    
    final entry = _document!.delete(id);
    if (entry != null) {
      await _persist();
      _changeController.add(CrdtChangeEvent.deleted(entry));
    }
    return entry;
  }
  
  /// Get all active (non-deleted) entries
  List<Map<String, dynamic>> getActiveEntries() {
    if (_document == null) return [];
    return _document!.activeEntries
      .map((e) => jsonDecode(e.data) as Map<String, dynamic>)
      .toList();
  }
  
  /// Import entries from legacy JSON format
  Future<void> importFromJson(String json) async {
    if (_document == null) throw StateError('CRDT not initialized');
    
    final list = jsonDecode(json) as List<dynamic>;
    for (final item in list) {
      final map = item as Map<String, dynamic>;
      final id = map['id'] as String? ?? const Uuid().v4();
      _document!.upsert(id, jsonEncode(map));
    }
    await _persist();
    _changeController.add(CrdtChangeEvent.bulkUpdate());
  }
  
  /// Export to legacy JSON format
  String exportToJson() {
    final entries = getActiveEntries();
    return jsonEncode(entries);
  }
  
  /// Merge remote changes into local document
  Future<List<CrdtEntry>> mergeRemote(CrdtDocument remote) async {
    if (_document == null) throw StateError('CRDT not initialized');
    
    final updated = _document!.merge(remote);
    if (updated.isNotEmpty) {
      await _persist();
      _changeController.add(CrdtChangeEvent.merged(updated.length));
    }
    return updated;
  }
  
  /// Merge a single remote entry
  Future<bool> mergeRemoteEntry(CrdtEntry entry) async {
    if (_document == null) throw StateError('CRDT not initialized');
    
    final merged = _document!.mergeEntry(entry);
    if (merged) {
      await _persist();
      _changeController.add(CrdtChangeEvent.updated(entry));
    }
    return merged;
  }
  
  /// Serialize document for sync (encrypted)
  Future<Uint8List> serializeEncrypted(SecretKey key) async {
    if (_document == null) throw StateError('CRDT not initialized');
    
    final json = jsonEncode(_document!.toJson());
    return await _encryptData(key, json);
  }
  
  /// Deserialize encrypted document from peer
  Future<CrdtDocument> deserializeEncrypted(SecretKey key, Uint8List data) async {
    final json = await _decryptData(key, data);
    return CrdtDocument.fromJson(jsonDecode(json) as Map<String, dynamic>);
  }
  
  /// Get delta since timestamp for incremental sync
  CrdtDocument getDelta({required int sinceTimestamp}) {
    if (_document == null) throw StateError('CRDT not initialized');
    return _document!.delta(sinceTimestamp: sinceTimestamp);
  }
  
  Future<Uint8List> _encryptData(SecretKey key, String plaintext) async {
    final aes = AesGcm.with256bits();
    final nonce = aes.newNonce();
    final secretBox = await aes.encrypt(
      utf8.encode(plaintext),
      secretKey: key,
      nonce: nonce,
    );
    
    // Format: nonce || ciphertext || mac
    final output = BytesBuilder();
    output.add(secretBox.nonce);
    output.add(secretBox.cipherText);
    output.add(secretBox.mac.bytes);
    return Uint8List.fromList(output.toBytes());
  }
  
  Future<String> _decryptData(SecretKey key, Uint8List data) async {
    final aes = AesGcm.with256bits();
    const nonceLen = 12;
    const macLen = 16;
    
    final nonce = data.sublist(0, nonceLen);
    final cipherText = data.sublist(nonceLen, data.length - macLen);
    final mac = Mac(data.sublist(data.length - macLen));
    
    final secretBox = SecretBox(cipherText, nonce: nonce, mac: mac);
    final clear = await aes.decrypt(secretBox, secretKey: key);
    return utf8.decode(clear);
  }
  
  /// Close the service
  Future<void> close() async {
    await _changeController.close();
    await _box?.close();
  }
}

/// Events emitted when CRDT document changes
abstract class CrdtChangeEvent {
  const CrdtChangeEvent();
  
  factory CrdtChangeEvent.updated(CrdtEntry entry) = CrdtEntryUpdatedEvent;
  factory CrdtChangeEvent.deleted(CrdtEntry entry) = CrdtEntryDeletedEvent;
  factory CrdtChangeEvent.merged(int count) = CrdtMergedEvent;
  factory CrdtChangeEvent.bulkUpdate() = CrdtBulkUpdateEvent;
}

class CrdtEntryUpdatedEvent extends CrdtChangeEvent {
  final CrdtEntry entry;
  const CrdtEntryUpdatedEvent(this.entry);
}

class CrdtEntryDeletedEvent extends CrdtChangeEvent {
  final CrdtEntry entry;
  const CrdtEntryDeletedEvent(this.entry);
}

class CrdtMergedEvent extends CrdtChangeEvent {
  final int count;
  const CrdtMergedEvent(this.count);
}

class CrdtBulkUpdateEvent extends CrdtChangeEvent {
  const CrdtBulkUpdateEvent();
}
