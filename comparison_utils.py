class APKComparator:
    def __init__(self, apk_data1, apk_data2):
        self.apk1 = apk_data1
        self.apk2 = apk_data2
    
    def compare(self):
        """Compare two APK analysis results"""
        comparison_data = {
            'identical_permissions': 0,
            'different_permissions': 0,
            'signature_match': False,
            'differences': {
                'basic_info': [],
                'permissions': [],
                'features': [],
                'signature': [],
                'components': []
            }
        }
        
        # Compare basic information
        comparison_data['differences']['basic_info'] = self._compare_basic_info()
        
        # Compare permissions
        perm_comparison = self._compare_permissions()
        comparison_data['identical_permissions'] = perm_comparison['identical']
        comparison_data['different_permissions'] = perm_comparison['different']
        comparison_data['differences']['permissions'] = perm_comparison['differences']
        
        # Compare features
        comparison_data['differences']['features'] = self._compare_features()
        
        # Compare signatures
        sig_comparison = self._compare_signatures()
        comparison_data['signature_match'] = sig_comparison['match']
        comparison_data['differences']['signature'] = sig_comparison['differences']
        
        # Compare components
        comparison_data['differences']['components'] = self._compare_components()
        
        return comparison_data
    
    def _compare_basic_info(self):
        """Compare basic app information"""
        differences = []
        
        fields_to_compare = [
            ('app_name', 'App Name'),
            ('package_name', 'Package Name'),
            ('version_name', 'Version Name'),
            ('version_code', 'Version Code'),
            ('min_sdk_version', 'Min SDK Version'),
            ('target_sdk_version', 'Target SDK Version'),
            ('debuggable', 'Debuggable'),
            ('architectures', 'Architectures')
        ]
        
        for field, display_name in fields_to_compare:
            val1 = self.apk1.get(field, 'Unknown')
            val2 = self.apk2.get(field, 'Unknown')
            
            if val1 != val2:
                differences.append(f"{display_name}: APK1='{val1}' vs APK2='{val2}'")
        
        return differences
    
    def _compare_permissions(self):
        """Compare permissions between APKs"""
        perms1 = set(self.apk1.get('permissions', {}).get('declared', []))
        perms2 = set(self.apk2.get('permissions', {}).get('declared', []))
        
        identical = len(perms1.intersection(perms2))
        only_in_1 = perms1 - perms2
        only_in_2 = perms2 - perms1
        different = len(only_in_1) + len(only_in_2)
        
        differences = []
        
        if only_in_1:
            differences.append(f"Only in APK1: {', '.join(sorted(only_in_1))}")
        
        if only_in_2:
            differences.append(f"Only in APK2: {', '.join(sorted(only_in_2))}")
        
        return {
            'identical': identical,
            'different': different,
            'differences': differences
        }
    
    def _compare_features(self):
        """Compare features between APKs"""
        differences = []
        
        features1 = set(self.apk1.get('features', {}).get('required', []))
        features2 = set(self.apk2.get('features', {}).get('required', []))
        
        only_in_1 = features1 - features2
        only_in_2 = features2 - features1
        
        if only_in_1:
            differences.append(f"Features only in APK1: {', '.join(sorted(only_in_1))}")
        
        if only_in_2:
            differences.append(f"Features only in APK2: {', '.join(sorted(only_in_2))}")
        
        return differences
    
    def _compare_signatures(self):
        """Compare signature information"""
        sig1 = self.apk1.get('signature', {})
        sig2 = self.apk2.get('signature', {})
        
        differences = []
        match = True
        
        # Compare signer
        signer1 = sig1.get('signer', 'Unknown')
        signer2 = sig2.get('signer', 'Unknown')
        if signer1 != signer2:
            differences.append(f"Signer: APK1='{signer1}' vs APK2='{signer2}'")
            match = False
        
        # Compare algorithm
        algo1 = sig1.get('algorithm', 'Unknown')
        algo2 = sig2.get('algorithm', 'Unknown')
        if algo1 != algo2:
            differences.append(f"Algorithm: APK1='{algo1}' vs APK2='{algo2}'")
            match = False
        
        # Compare signature schemes
        schemes1 = sig1.get('schemes', {})
        schemes2 = sig2.get('schemes', {})
        
        for scheme in schemes1:
            if scheme in schemes2:
                if schemes1[scheme] != schemes2[scheme]:
                    status1 = "Verified" if schemes1[scheme] else "Not verified"
                    status2 = "Verified" if schemes2[scheme] else "Not verified"
                    differences.append(f"{scheme}: APK1={status1} vs APK2={status2}")
                    match = False
        
        return {
            'match': match,
            'differences': differences
        }
    
    def _compare_components(self):
        """Compare app components (activities, services, etc.)"""
        differences = []
        
        # Compare activities
        activities1 = set(self.apk1.get('activities', []))
        activities2 = set(self.apk2.get('activities', []))
        
        if activities1 != activities2:
            only_1 = activities1 - activities2
            only_2 = activities2 - activities1
            
            if only_1:
                differences.append(f"Activities only in APK1: {len(only_1)} components")
            if only_2:
                differences.append(f"Activities only in APK2: {len(only_2)} components")
        
        # Compare services
        services1 = set(self.apk1.get('services', []))
        services2 = set(self.apk2.get('services', []))
        
        if services1 != services2:
            only_1 = services1 - services2
            only_2 = services2 - services1
            
            if only_1:
                differences.append(f"Services only in APK1: {len(only_1)} components")
            if only_2:
                differences.append(f"Services only in APK2: {len(only_2)} components")
        
        return differences
