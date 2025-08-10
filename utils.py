def format_size(bytes_size):
    """Format file size in human readable format"""
    if bytes_size == 0:
        return "0 B"
    
    units = ['B', 'KB', 'MB', 'GB', 'TB']
    size = bytes_size
    unit_index = 0
    
    while size >= 1024 and unit_index < len(units) - 1:
        size /= 1024
        unit_index += 1
    
    if unit_index == 0:
        return f"{int(size)} {units[unit_index]}"
    else:
        return f"{size:.2f} {units[unit_index]}"

def safe_get(data, key, default=None):
    """Safely get value from dictionary with default"""
    try:
        if isinstance(data, dict):
            return data.get(key, default)
        else:
            return default
    except:
        return default

def clean_package_name(package_name):
    """Clean and format package name"""
    if not package_name or package_name == 'Unknown':
        return 'Unknown'
    
    # Remove common prefixes if needed
    if package_name.startswith('com.'):
        return package_name
    else:
        return package_name

def format_permission_name(permission):
    """Format permission name for display"""
    if not permission:
        return 'Unknown'
    
    # Remove android.permission prefix for cleaner display
    if permission.startswith('android.permission.'):
        return permission[19:]  # Remove 'android.permission.' prefix
    elif permission.startswith('com.android.'):
        return permission[12:]  # Remove 'com.android.' prefix
    else:
        return permission

def format_feature_name(feature):
    """Format feature name for display"""
    if not feature:
        return 'Unknown'
    
    # Remove android.hardware prefix for cleaner display
    if feature.startswith('android.hardware.'):
        return feature[17:]  # Remove 'android.hardware.' prefix
    elif feature.startswith('android.software.'):
        return feature[17:]  # Remove 'android.software.' prefix
    else:
        return feature

def get_security_level(permissions):
    """Determine security risk level based on permissions"""
    if not permissions:
        return "Low", "No sensitive permissions detected"
    
    high_risk_permissions = [
        'READ_CONTACTS', 'WRITE_CONTACTS',
        'READ_CALENDAR', 'WRITE_CALENDAR',
        'ACCESS_FINE_LOCATION', 'ACCESS_COARSE_LOCATION',
        'RECORD_AUDIO', 'CAMERA',
        'READ_PHONE_STATE', 'CALL_PHONE',
        'READ_SMS', 'SEND_SMS', 'RECEIVE_SMS',
        'WRITE_EXTERNAL_STORAGE',
        'SYSTEM_ALERT_WINDOW',
        'WRITE_SETTINGS'
    ]
    
    medium_risk_permissions = [
        'INTERNET', 'ACCESS_NETWORK_STATE',
        'ACCESS_WIFI_STATE', 'CHANGE_WIFI_STATE',
        'BLUETOOTH', 'BLUETOOTH_ADMIN',
        'VIBRATE', 'WAKE_LOCK'
    ]
    
    declared_perms = [format_permission_name(p) for p in permissions.get('declared', [])]
    
    high_risk_count = sum(1 for perm in declared_perms if perm in high_risk_permissions)
    medium_risk_count = sum(1 for perm in declared_perms if perm in medium_risk_permissions)
    
    if high_risk_count >= 5:
        return "High", f"Multiple sensitive permissions detected ({high_risk_count} high-risk)"
    elif high_risk_count >= 2:
        return "Medium-High", f"Several sensitive permissions detected ({high_risk_count} high-risk)"
    elif high_risk_count >= 1:
        return "Medium", f"Some sensitive permissions detected ({high_risk_count} high-risk)"
    elif medium_risk_count >= 3:
        return "Medium-Low", f"Standard permissions with network access ({medium_risk_count} medium-risk)"
    else:
        return "Low", "Minimal permissions requested"

def validate_apk_file(file):
    """Validate if uploaded file is a valid APK"""
    if not file:
        return False, "No file provided"
    
    if not file.name.lower().endswith('.apk'):
        return False, "File must have .apk extension"
    
    # Check file size (limit to 100MB for this demo)
    if file.size > 100 * 1024 * 1024:
        return False, "File size too large (max 100MB)"
    
    return True, "Valid APK file"
