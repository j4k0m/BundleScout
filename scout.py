import os
import zipfile
import re
import json
from androguard.core.bytecodes.apk import APK
from androguard.core.bytecodes.dvm import DalvikVMFormat
from androguard.core.analysis.analysis import Analysis
import click
from colorama import init, Fore, Style
import tempfile
import shutil

init()

class ReactNativeAPKAnalyzer:
    def __init__(self, apk_path):
        self.apk_path = apk_path
        self.temp_dir = tempfile.mkdtemp()
        self.secrets = []
        self.endpoints = []

    def cleanup(self):
        shutil.rmtree(self.temp_dir)

    def extract_apk(self):
        try:
            with zipfile.ZipFile(self.apk_path, 'r') as apk_zip:
                apk_zip.extractall(self.temp_dir)
            click.echo(f"{Fore.GREEN}✓ APK extracted successfully{Style.RESET_ALL}")
            return True
        except Exception as e:
            click.echo(f"{Fore.RED}✗ Failed to extract APK: {str(e)}{Style.RESET_ALL}")
            return False

    def find_bundle(self):
        bundle_patterns = [
            'assets/index.android.bundle',
            'assets/index.bundle'
        ]
        
        for pattern in bundle_patterns:
            bundle_path = os.path.join(self.temp_dir, pattern)
            if os.path.exists(bundle_path):
                click.echo(f"{Fore.GREEN}✓ Found React Native bundle: {pattern}{Style.RESET_ALL}")
                
                bundle_output_dir = os.path.join(self.temp_dir, 'extracted_bundle')
                os.makedirs(bundle_output_dir, exist_ok=True)
                
                bundle_copy = os.path.join(bundle_output_dir, 'index.bundle')
                shutil.copy2(bundle_path, bundle_copy)
                
                return bundle_path
        
        click.echo(f"{Fore.YELLOW}! No React Native bundle found{Style.RESET_ALL}")
        return None

    def analyze_bundle(self, bundle_path, output_dir=None):
        try:
            with open(bundle_path, 'r', encoding='utf-8') as f:
                content = f.read()

            if output_dir:
                bundle_output_dir = output_dir
                os.makedirs(bundle_output_dir, exist_ok=True)
            else:
                bundle_output_dir = os.path.join(self.temp_dir, 'extracted_bundle')
                os.makedirs(bundle_output_dir, exist_ok=True)

            self.decompile_bundle(bundle_path, bundle_output_dir)
            self.analyze_js_files(bundle_output_dir)
            self.analyze_bundle_structure(content, bundle_output_dir)
            self.extract_modules(content, bundle_output_dir)

        except Exception as e:
            click.echo(f"{Fore.RED}✗ Failed to analyze bundle: {str(e)}{Style.RESET_ALL}")

    def analyze_js_files(self, bundle_output_dir):
        patterns = {
            'URL Patterns': [
                r'[\'"`]https?://[\'"`]\s*\+\s*[\w.]+\s*\+\s*[\'"`][^\'"`]+[\'"`]',
                r'[\'"`]https?://[^\'"}`]+[\'"`]\s*\+\s*[\w.]+',
                r'o\s*=\s*[\'"`]https?://[^\'"}`]*[\'"`]\s*\+\s*[\w.]+\s*\+\s*[\'"`][^\'"}`]*[\'"`]',
                r'[\'"`]https?://[^\'"}`]+\?[\w=&]+(?:&[\w=&]+)*[\'"`]',
                r'[\'"`]/[\w-]+\?[\w=&]+(?:&[\w=&]+)*[\'"`]',
                r'url\.split\([\'"`]\?[\'"`]\)[0]',
                r'parseUrl\([\'"`]([^\'"`]+(?:\?[\w=&]+(?:&[\w=&]+)*)?)[\'"`]',
                r'serverUrl\s*\+\s*[^+]+\+\s*[\'"`]\?platform=[^\'"`]+(?:&[\w=&]+)*[\'"`]',
                r'(?:fetch|axios|XMLHttpRequest)\s*\(\s*[\'"`]([^\'"`]+(?:\?[\w=&]+(?:&[\w=&]+)*)?)[\'"`]\)',
                r'(?:get|post|put|delete|patch)\s*\(\s*[\'"`]([^\'"`]+(?:\?[\w=&]+(?:&[\w=&]+)*)?)[\'"`]'
            ]
        }

        simple_url_pattern = r'https?://[^\s\'"`]+(?:\?[\w=&]+(?:&[\w=&]+)*)?'

        for root, _, files in os.walk(bundle_output_dir):
            for js_file in files:
                if not js_file.endswith('.js'):
                    continue

                try:
                    with open(os.path.join(root, js_file), 'r', encoding='utf-8') as f:
                        content = f.read()
                        
                        concat_pattern = r'(?:var\s+)?[a-zA-Z_]\s*=\s*[\'"`]https?://[\'"`]\s*\+\s*[\w.]+\s*\+\s*[\'"`][^\'"`]+[\'"`]'
                        matches = re.finditer(concat_pattern, content, re.MULTILINE)
                        for match in matches:
                            url_parts = re.findall(r'[\'"`](.*?)[\'"`]', match.group(0))
                            if url_parts:
                                reconstructed_url = ''.join(url_parts).replace('" + "', '')
                                if self._is_relevant_url(reconstructed_url):
                                    self.endpoints.append(('API Endpoint', reconstructed_url))

                        for pattern in patterns['URL Patterns']:
                            matches = re.finditer(pattern, content, re.MULTILINE)
                            for match in matches:
                                found_url = match.group(1) if match.groups() else match.group(0)
                                found_url = found_url.strip('\'"`')
                                if self._is_relevant_url(found_url):
                                    self.endpoints.append(('API Endpoint', found_url))

                        simple_matches = re.finditer(simple_url_pattern, content)
                        for match in simple_matches:
                            found_url = match.group(0)
                            if self._is_relevant_url(found_url):
                                self.endpoints.append(('URL', found_url))

                        secret_patterns = [
                            (r'api[_-]?key["\'\s]*[:=]\s*["\']([^"\']+)["\']', 'API Key'),
                            (r'secret[_-]?key["\'\s]*[:=]\s*["\']([^"\']+)["\']', 'Secret Key'),
                            (r'password["\'\s]*[:=]\s*["\']([^"\']+)["\']', 'Password'),
                            (r'token["\'\s]*[:=]\s*["\']([^"\']+)["\']', 'Token')
                        ]
                        
                        for pattern, secret_type in secret_patterns:
                            matches = re.finditer(pattern, content, re.IGNORECASE)
                            for match in matches:
                                self.secrets.append((secret_type, match.group(1)))

                except Exception as e:
                    click.echo(f"{Fore.RED}✗ Failed to analyze {js_file}: {str(e)}{Style.RESET_ALL}")

    def _is_valid_url(self, url):
        if not url:
            return False
        
        skip_patterns = [
            r'^/$',
            r'^/static/',
            r'^/assets/',
            r'^/public/',
            r'^/images/',
            r'^/\w+\.(?:js|css|html)$'
        ]
        
        for pattern in skip_patterns:
            if re.match(pattern, url):
                return False

        return (
            url.startswith(('http://', 'https://', '/api/', '/v1/', '/v2/')) or
            re.match(r'^/[\w-]+/[\w-]+', url)
        )

    def analyze_bundle_structure(self, content, output_dir):
        try:
            module_pattern = r'__d\(function\s*\(([^)]*)\)\s*{([^}]*)}'
            modules = re.finditer(module_pattern, content)

            require_pattern = r'require\([\'"]([^\'"]+)[\'"]\)'
            requires = re.findall(require_pattern, content)

            rn_patterns = {
                'Components': r'React\.Component|React\.PureComponent',
                'Hooks': r'useState|useEffect|useContext|useReducer|useCallback|useMemo|useRef',
                'Navigation': r'Navigation|Router|Screen|Stack',
                'Redux': r'createStore|Provider|connect|useSelector|useDispatch',
                'Network': r'fetch|axios|XMLHttpRequest',
                'Storage': r'AsyncStorage|Storage',
            }

            click.echo(f"\n{Fore.CYAN}Bundle Structure Analysis:{Style.RESET_ALL}")
            
            module_count = len(list(re.finditer(module_pattern, content)))
            click.echo(f"{Fore.GREEN}• Total modules found: {module_count}{Style.RESET_ALL}")
            
            unique_requires = set(requires)
            click.echo(f"{Fore.GREEN}• Total unique requires: {len(unique_requires)}{Style.RESET_ALL}")

            for pattern_name, pattern in rn_patterns.items():
                matches = len(re.findall(pattern, content))
                if matches > 0:
                    click.echo(f"{Fore.GREEN}• {pattern_name} usage found: {matches} occurrences{Style.RESET_ALL}")

        except Exception as e:
            click.echo(f"{Fore.RED}✗ Failed to analyze bundle structure: {str(e)}{Style.RESET_ALL}")

    def extract_modules(self, content, output_dir):
        try:
            modules_dir = os.path.join(output_dir, 'modules')
            os.makedirs(modules_dir, exist_ok=True)

            module_pattern = r'__d\(\s*function\s*\(([^)]*)\)\s*{([\s\S]*?)},\s*(\d+)\s*,\s*\[([^\]]*)\]\s*\)'
            modules = re.finditer(module_pattern, content)

            click.echo(f"\n{Fore.CYAN}Module Analysis:{Style.RESET_ALL}")
            
            module_count = 0
            interesting_modules = []

            for i, module in enumerate(modules):
                try:
                    module_content = module.group(2)
                    module_params = module.group(1)
                    module_id = module.group(3)

                    interesting_patterns = {
                        'API': r'(?:fetch|axios|http|api)\s*\.\s*(?:get|post|put|delete)',
                        'URL': r'(?:url|endpoint|baseURL)\s*[:=]\s*[\'"`]([^\'"`]+)[\'"`]',
                        'Auth': r'(?:auth|login|token|bearer)',
                        'Storage': r'(?:storage|cache|persist)',
                        'Sensitive': r'(?:password|secret|key|apiKey)',
                        'Config': r'(?:config|settings|env)'
                    }

                    is_interesting = False
                    matched_patterns = []

                    for pattern_name, pattern in interesting_patterns.items():
                        if re.search(pattern, module_content, re.IGNORECASE):
                            is_interesting = True
                            matched_patterns.append(pattern_name)

                    if is_interesting:
                        module_filename = f'module_{module_id}_{"-".join(matched_patterns)}.js'
                        module_path = os.path.join(modules_dir, module_filename)
                        
                        try:
                            import jsbeautifier
                            formatted_content = jsbeautifier.beautify(module_content)
                        except ImportError:
                            formatted_content = module_content

                        with open(module_path, 'w', encoding='utf-8') as f:
                            f.write(f'// Module ID: {module_id}\n')
                            f.write(f'// Parameters: {module_params}\n\n')
                            f.write(formatted_content)
                        
                        interesting_modules.append((module_filename, matched_patterns))
                        module_count += 1

                        api_patterns = [
                            r'(?:fetch|axios)\s*\(\s*[\'"`]((?:https?:)?//[^\'"`]+|/[^\'"`]+)[\'"`]',
                            r'\.(?:get|post|put|delete)\s*\(\s*[\'"`]([^\'"}`]+)[\'"`]',
                            r'url:\s*[\'"`]([^\'"}`]+)[\'"`]',
                            r'baseURL:\s*[\'"`]([^\'"}`]+)[\'"`]'
                        ]

                        for pattern in api_patterns:
                            matches = re.finditer(pattern, module_content, re.IGNORECASE)
                            for match in matches:
                                endpoint = match.group(1).strip('\'"`')
                                if self._is_relevant_url(endpoint):
                                    self.endpoints.append((endpoint, module_filename))

                except Exception as e:
                    click.echo(f"{Fore.RED}✗ Failed to process module {i}: {str(e)}{Style.RESET_ALL}")
                    continue

            if interesting_modules:
                click.echo(f"\n{Fore.GREEN}Found {module_count} interesting modules:{Style.RESET_ALL}")
                for filename, patterns in interesting_modules:
                    click.echo(f"{Fore.GREEN}• {filename}{Style.RESET_ALL}")
                    click.echo(f"  Contains: {', '.join(patterns)}")

            if self.endpoints:
                click.echo(f"\n{Fore.GREEN}Found API Endpoints:{Style.RESET_ALL}")
                for endpoint, source in self.endpoints:
                    click.echo(f"{Fore.GREEN}• {endpoint} (in {source}){Style.RESET_ALL}")

        except Exception as e:
            click.echo(f"{Fore.RED}✗ Failed to extract modules: {str(e)}{Style.RESET_ALL}")

    def analyze_native_code(self):
        try:
            apk = APK(self.apk_path)
            dvm = DalvikVMFormat(apk)
            analysis = Analysis(dvm)

            click.echo(f"\n{Fore.CYAN}APK Information:{Style.RESET_ALL}")
            click.echo(f"Package: {Fore.GREEN}{apk.get_package()}{Style.RESET_ALL}")
            click.echo(f"Version: {Fore.GREEN}{apk.get_androidversion_name()}{Style.RESET_ALL}")
            click.echo(f"SDK Version: {Fore.GREEN}{apk.get_target_sdk_version()}{Style.RESET_ALL}")

            for string in analysis.get_strings():
                if re.match(r'https?://', string):
                    self.endpoints.append(string)
                
                if any(keyword in string.lower() for keyword in ['api', 'key', 'secret', 'token', 'password']):
                    self.secrets.append(('Native Code Secret', string))

            click.echo(f"{Fore.GREEN}✓ Native code analysis complete{Style.RESET_ALL}")
        except Exception as e:
            click.echo(f"{Fore.RED}✗ Failed to analyze native code: {str(e)}{Style.RESET_ALL}")

    def display_results(self):
        click.echo(f"\n{Fore.CYAN}Bundle Location:{Style.RESET_ALL}")
        click.echo(f"{Fore.GREEN}• Extracted bundle directory: {os.path.join(self.temp_dir, 'extracted_bundle')}{Style.RESET_ALL}")

        click.echo(f"\n{Fore.CYAN}Found Endpoints:{Style.RESET_ALL}")
        if self.endpoints:
            endpoint_types = {}
            for endpoint_type, endpoint in self.endpoints:
                if endpoint_type not in endpoint_types:
                    endpoint_types[endpoint_type] = set()
                endpoint_types[endpoint_type].add(endpoint)

            for endpoint_type, endpoints in endpoint_types.items():
                click.echo(f"\n{Fore.GREEN}{endpoint_type}:{Style.RESET_ALL}")
                for endpoint in endpoints:
                    click.echo(f"{Fore.GREEN}• {endpoint}{Style.RESET_ALL}")
        else:
            click.echo(f"{Fore.YELLOW}No endpoints found{Style.RESET_ALL}")

        click.echo(f"\n{Fore.CYAN}Potential Secrets:{Style.RESET_ALL}")
        if self.secrets:
            for secret_type, secret in set(self.secrets):
                click.echo(f"{Fore.YELLOW}• {secret_type}: {secret}{Style.RESET_ALL}")
        else:
            click.echo(f"{Fore.YELLOW}No secrets found{Style.RESET_ALL}")

    def decompile_bundle(self, bundle_path, output_dir):
        try:
            with open(bundle_path, 'r', encoding='utf-8') as f:
                content = f.read()

            modules_dir = os.path.join(output_dir, 'modules')
            components_dir = os.path.join(output_dir, 'components')
            screens_dir = os.path.join(output_dir, 'screens')
            utils_dir = os.path.join(output_dir, 'utils')
            
            for directory in [modules_dir, components_dir, screens_dir, utils_dir]:
                os.makedirs(directory, exist_ok=True)

            module_pattern = r'__d\(\s*function\s*\(([^)]*)\)\s*{\s*([\s\S]*?)\s*},\s*(\d+)\s*,\s*\[([^\]]*)\]\s*\)'
            modules = re.finditer(module_pattern, content)

            click.echo(f"\n{Fore.CYAN}Decompiling Bundle:{Style.RESET_ALL}")
            
            module_info = {}
            module_count = 0

            for module in modules:
                try:
                    params = module.group(1)
                    body = module.group(2)
                    module_id = module.group(3)
                    dependencies = module.group(4)

                    try:
                        import jsbeautifier
                        formatted_code = jsbeautifier.beautify(body)
                    except ImportError:
                        formatted_code = body

                    module_type = 'modules'
                    if re.search(r'React\.Component|React\.PureComponent', formatted_code):
                        if re.search(r'Screen|Navigator|Route', formatted_code):
                            module_type = 'screens'
                        else:
                            module_type = 'components'
                    elif re.search(r'export\s+(?:function|const|let|var|default)', formatted_code):
                        module_type = 'utils'

                    module_name = f"module_{module_id}"
                    name_match = re.search(r'(?:require|import)\s*\([\'"]([^\'"]+)[\'"]\)', formatted_code)
                    if name_match:
                        module_name = name_match.group(1).replace('/', '_').replace('-', '_')

                    module_info[module_id] = {
                        'name': module_name,
                        'type': module_type,
                        'dependencies': [d.strip() for d in dependencies.split(',') if d.strip()],
                        'params': [p.strip() for p in params.split(',') if p.strip()]
                    }

                    output_subdir = os.path.join(output_dir, module_type)
                    file_path = os.path.join(output_subdir, f"{module_name}.js")

                    header = f"""/**
 * Module ID: {module_id}
 * Type: {module_type}
 * Dependencies: {dependencies}
 * Parameters: {params}
 */

"""

                    with open(file_path, 'w', encoding='utf-8') as f:
                        f.write(header + formatted_code)

                    module_count += 1
                    if module_count % 100 == 0:
                        click.echo(f"{Fore.GREEN}• Processed {module_count} modules{Style.RESET_ALL}")

                except Exception as e:
                    click.echo(f"{Fore.RED}✗ Failed to process module {module_id}: {str(e)}{Style.RESET_ALL}")
                    continue

            with open(os.path.join(output_dir, 'module_info.json'), 'w') as f:
                json.dump(module_info, f, indent=2)

            click.echo(f"{Fore.GREEN}✓ Successfully decompiled {module_count} modules{Style.RESET_ALL}")
            click.echo(f"{Fore.GREEN}✓ Output saved to: {output_dir}{Style.RESET_ALL}")

        except Exception as e:
            click.echo(f"{Fore.RED}✗ Failed to decompile bundle: {str(e)}{Style.RESET_ALL}")

    def analyze_modules(self, modules_dir):
        patterns = {
            'HTTP Methods': [
                r'(?:fetch|axios|http)\s*\.\s*(?:get|post|put|delete|patch)\s*\(\s*[\'"`]([^\'"`]+)[\'"`]',
                r'XMLHttpRequest\s*\(\s*[\'"`]([^\'"`]+)[\'"`]'
            ],
            'URL Construction': [
                r'url\s*[:=]\s*[\'"`]([^\'"`]+)[\'"`]',
                r'baseURL\s*[:=]\s*[\'"`]([^\'"`]+)[\'"`]',
                r'endpoint\s*[:=]\s*[\'"`]([^\'"`]+)[\'"`]',
                r'[\'"`](https?://[^\'"`]+|/api/[^\'"`]+)[\'"`]'
            ],
            'Dynamic URLs': [
                r'`[^`]*\${[^}]+}[^`]*`',
                r'[\'"`]/[^\'"`]+\?[^\'"`]+[\'"`]',
                r'[\'"`](?:https?://)?[\w.-]+/[\w.-]+\?[\w=&]+[\'"`]'
            ]
        }

        findings = {
            'URLs': set(),
            'API Endpoints': set(),
            'API Calls': set()
        }

        http_methods = ['DELETE', 'GET', 'HEAD', 'OPTIONS', 'POST', 'PUT']

        for js_file in os.listdir(modules_dir):
            if not js_file.endswith('.js'):
                continue

            try:
                with open(os.path.join(modules_dir, js_file), 'r', encoding='utf-8') as f:
                    content = f.read()

                    for method in http_methods:
                        method_pattern = fr'{method}\s*,\s*[\'"`]([^\'"`]+)[\'"`]'
                        matches = re.finditer(method_pattern, content, re.IGNORECASE)
                        for match in matches:
                            endpoint = match.group(1)
                            if self._is_relevant_url(endpoint):
                                findings['API Calls'].add(f"{method} {endpoint} (in {js_file})")

                    for category, category_patterns in patterns.items():
                        for pattern in category_patterns:
                            matches = re.finditer(pattern, content, re.MULTILINE)
                            for match in matches:
                                found_url = match.group(0).strip('\'"`')
                                if self._is_relevant_url(found_url):
                                    if 'http' in found_url.lower() or '://' in found_url:
                                        findings['URLs'].add(f"{found_url} (in {js_file})")
                                    elif '/api/' in found_url or found_url.startswith('/v'):
                                        findings['API Endpoints'].add(f"{found_url} (in {js_file})")
                                    else:
                                        findings['API Calls'].add(f"{found_url} (in {js_file})")

            except Exception as e:
                click.echo(f"{Fore.RED}✗ Failed to analyze {js_file}: {str(e)}{Style.RESET_ALL}")

        for category, items in findings.items():
            if items:
                click.echo(f"\n{Fore.GREEN}{category}:{Style.RESET_ALL}")
                for item in sorted(items):
                    click.echo(f"{Fore.GREEN}• {item}{Style.RESET_ALL}")
            else:
                click.echo(f"{Fore.YELLOW}No {category.lower()} found{Style.RESET_ALL}")

    def _is_relevant_url(self, url):
        skip_domains = [
            'facebook.github.io',
            'reactjs.org',
            'github.com',
            'localhost',
            'example.com'
        ]
        
        skip_paths = [
            '/static/',
            '/assets/',
            '/images/',
            '/docs/',
            '/css/',
            '/js/'
        ]

        for domain in skip_domains:
            if domain in url.lower():
                return False

        for path in skip_paths:
            if path in url:
                return False

        return (
            url.startswith(('http://', 'https://', '/api/', '/v1/', '/v2/')) or
            re.match(r'^/[\w-]+/[\w-]+', url) or
            '${' in url or
            bool(re.search(r'/\w+\?', url))
        )

@click.command()
@click.argument('apk_path', type=click.Path(exists=True))
@click.option('--save-json', is_flag=True, help='Save results to JSON file')
@click.option('--output-dir', type=click.Path(), help='Directory to save the extracted bundle')
def analyze_apk(apk_path, save_json, output_dir):
    click.echo(f"\n{Fore.CYAN}Starting APK analysis...{Style.RESET_ALL}")
    
    analyzer = ReactNativeAPKAnalyzer(apk_path)
    
    try:
        if analyzer.extract_apk():
            bundle_path = analyzer.find_bundle()
            if bundle_path:
                analyzer.analyze_bundle(bundle_path, output_dir)
            
            click.echo(f"\n{Fore.CYAN}Analyzing native code...{Style.RESET_ALL}")
            analyzer.analyze_native_code()
            
            analyzer.display_results()

            if save_json:
                report = {
                    'endpoints': list(set(analyzer.endpoints)),
                    'secrets': list(set(analyzer.secrets))
                }
                with open('analysis_report.json', 'w') as f:
                    json.dump(report, f, indent=4)
                click.echo(f"\n{Fore.GREEN}✓ Report saved to analysis_report.json{Style.RESET_ALL}")
    
    finally:
        analyzer.cleanup()

if __name__ == "__main__":
    analyze_apk() 
