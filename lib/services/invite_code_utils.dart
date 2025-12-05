import 'dart:math';

/// Utility class for generating and validating invite codes.
/// 
/// Invite codes are 8-character case-sensitive alphanumeric strings
/// used for peer discovery in P2P sync.
/// 
/// Example codes: Ab3Xy9Zk, xY7mNp2Q
class InviteCodeUtils {
  static const String _chars = 
    'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  static const int length = 8;
  
  /// Generate a cryptographically secure random invite code.
  static String generate() {
    final random = Random.secure();
    return List.generate(
      length, 
      (_) => _chars[random.nextInt(_chars.length)]
    ).join();
  }
  
  /// Validate that a string is a valid invite code.
  /// Returns true if the code is exactly 8 alphanumeric characters.
  static bool isValid(String code) {
    return RegExp(r'^[A-Za-z0-9]{8}$').hasMatch(code);
  }
}
