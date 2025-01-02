from mac_vendor_lookup import MacLookup

# Update vendor database before performing lookups
try:
    print("Updating MAC vendor database...")
    MacLookup().update_vendors()
    print("MAC vendor database updated.")
except Exception as e:
    print(f"Error updating MAC vendor database: {e}")
