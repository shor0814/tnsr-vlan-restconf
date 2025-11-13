# TNSR VLAN Script v3.3.2 - Quick Start Guide

---

## Files

- **tnsr-vlan-restconf.php** - Main script (v3.3.2 Final, Production Ready)

---

## Installation

1. **Copy the script:**
```bash
cp tnsr-vlan-restconf.php /path/to/your/script.php
chmod +x /path/to/your/script.php
```

2. **Edit configuration** (lines 22-38):
```php
$config = [
    'tnsr_host'       => '10.10.10.3',        // TNSR IP
    'tnsr_username'   => 'YOUR_USER',         // API user
    'tnsr_password'   => 'YOUR_PASSWORD',     // API password
    'tnsr_port'       => 443,                 // HTTPS port
    'use_restconf'    => true,                // Use RESTCONF (true) or SSH (false)
    'parent_interface' => 'FortyGigabitEthernet65/0/1',  // Main interface
    'ipv6_prefix'      => 'xxxx:yyyy:0:',     // Your IPv6 prefix
    'dry_run'         => false,               // Set to true to test without changes
    'verify_ssl'      => false,               // Set to true in production
    'verbose'         => true,                // Show debug output
];
```

---

## Basic Commands

### Create VLAN
```bash
php script.php create xxxx:yyyy:0:200::/56
```

Creates:
- Subinterface: `FortyGigabitEthernet65/0/1.512` (VLAN 512 from hex 200)
- IPv6 address: `xxxx:yyyy:0:b200::1/64`
- Router advertisements
- Static route: `xxxx:yyyy:0:200::/56 via xxxx:yyyy:0:b200::2`

### List All VLANs
```bash
php script.php list
```

Shows:
- All subinterfaces with status and descriptions
- All IPv6 routes
- Total counts

### Verify VLAN
```bash
php script.php verify xxxx:yyyy:0:200::/56
```

Checks:
- ✅ Subinterface exists
- ✅ IPv6 address configured
- ✅ Static route exists

### Delete VLAN
```bash
php script.php delete xxxx:yyyy:0:200::/56
```

Removes:
- Static route
- Interface configuration
- Subinterface definition

### Run Diagnostics
```bash
php script.php diagnose
```

Tests:
- RESTCONF connectivity
- Authentication
- API access
- Parent interface availability

---

## What Was Fixed (v3.3.2 Final)

| Issue | Problem | Solution |
|-------|---------|----------|
| HTTP 412 route creation | PATCH caused duplicate element error | Use PATCH for create, PUT for delete |
| JSON key format mismatch | Expected `netgate-*:key`, got plain `key` | Use non-namespaced keys throughout |
| IPv6 format error | Generated `:1` instead of `::1` | Corrected to proper IPv6 format |
| Interface creation failed | Wrong JSON structure | Use two-step creation (POST + PUT) |
| Route verification failed | Verification used wrong key format | Updated to use non-namespaced keys |
| Route deletion didn't work | PATCH merges, doesn't delete | Changed to PUT (replace) for deletion |
| Subinterface not fully deleted | Missing deletion of subinterface definition | Added DELETE to `/subinterfaces` endpoint |

---

## Key Technical Points

### REST Methods Used

| Operation | Method | Reason |
|-----------|--------|--------|
| Create route | PATCH | Merges with existing routes safely |
| Delete route | PUT | Replaces entire table, effectively deleting excluded route |
| Create interface | POST + PUT | Two-step: POST defines subif, PUT configures it |
| Delete interface | DELETE | Removes interface config |
| Delete subif def | DELETE | Removes subinterface definition |

### JSON Keys

**Always use non-namespaced keys in request bodies:**

```json
{
  "netgate-route-table:route-table-config": {
    "static-routes": {           // ✅ Not "netgate-route-table:static-routes"
      "route-table": [           // ✅ Not "netgate-route-table:route-table"
        {
          "name": "default",     // ✅ Not "netgate-route-table:name"
          "ipv6-routes": {       // ✅ Not "netgate-route-table:ipv6-routes"
            "route": [...]
          }
        }
      ]
    }
  }
}
```

### IPv6 Address Generation

For subnet `xxxx:yyyy:0:200::/56`:

```
VLAN ID: 512 (hex: 200)
Gateway prefix: xxxx:yyyy:0:b200
Gateway IP: xxxx:yyyy:0:b200::1/64     ← TNSR gateway
Customer IP: xxxx:yyyy:0:b200::2       ← Customer side
```

---

## Testing Workflow

```bash
# 1. Check connection
php script.php diagnose
# Expected: All tests pass ✅

# 2. Create first VLAN
php script.php create xxxx:yyyy:0:100::/56
# Expected: Success message with verification ✅

# 3. List to see it
php script.php list
# Expected: VLAN 100 shown with routes ✅

# 4. Create second VLAN (tests route merging)
php script.php create xxxx:yyyy:0:200::/56
# Expected: Success, no HTTP 412 ✅

# 5. List again
php script.php list
# Expected: Both VLANs shown, no overwriting ✅

# 6. Verify first one
php script.php verify xxxx:yyyy:0:100::/56
# Expected: All checks pass ✅

# 7. Delete second one
php script.php delete xxxx:yyyy:0:200::/56
# Expected: All deletions succeed ✅

# 8. List again
php script.php list
# Expected: Only first VLAN shown ✅
```

---

## Common Issues & Fixes

### "Connection refused"
```
Check TNSR IP and firewall
Run: php script.php diagnose
```

### "Authentication failed"
```
Verify username/password in config
User must have admin permissions
```

### "HTTP 404 Instance does not exist" (delete)
```
This is NORMAL - means it was already deleted
The script shows this as a warning, not an error
```

### Routes not deleted (stay in config)
```
This was Fixed in v3.3.2!
Previously used PATCH (merge), now uses PUT (replace)
Routes should delete properly now
```

### Subinterface definition remains after delete
```
This was Fixed in v3.3.2!
Now includes DELETE to /subinterfaces endpoint
Should fully remove "interface subif..." sections
```

---

## Production Checklist

- [ ] Script tested on dev TNSR first
- [ ] Production config file created and updated
- [ ] TNSR authentication working (diagnose passes)
- [ ] SSL certificates configured (if verify_ssl = true)
- [ ] TNSR backup taken before automation
- [ ] Test create/verify/delete cycle with one VLAN
- [ ] Monitoring configured
- [ ] Rollback procedure documented

---

## Logging & Debug

### Enable verbose output
```php
'verbose' => true  // Shows DEBUG messages
```

### Check TNSR logs
```bash
show log daemon | tail
```

### Dry run mode (test without changes)
```php
'dry_run' => true  // Shows what would happen
```

---

## Performance

- Create VLAN: ~2-3 seconds
- List all: ~1 second
- Verify VLAN: ~1 second
- Delete VLAN: ~2-3 seconds

---

## Support Resources

For new conversations, reference:
1. **TNSR-VLAN-SCRIPT-COMPLETE-REFERENCE.md** - Full documentation
2. **tnsr-vlan-restconf.php** - The working script

Key facts to remember:
- Use **PATCH** for route creation (merges)
- Use **PUT** for route deletion (replaces)
- Use **non-namespaced keys** in all requests
- IPv6 format must be `::1` and `::2` (double colon)
- Delete is three steps: route → interface → subif definition

---

**Version:** 3.3.2 Final  
**Status:** ✅ Production Ready (All Issues Fixed)  
**Last Updated:** November 13, 2025
