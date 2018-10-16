package burp

data class Action (
        val enabled: Boolean,
        val match_cookies: String,
        val type: String)

data class ByAnnotation (
        val show_only_commented_items: Boolean,
        val show_only_highlighted_items: Boolean)

data class ByFileExtension (
        val hide_items: List<String>,
        val hide_specific: Boolean,
        val show_items: List<String>,
        val show_only_specific: Boolean)

data class ByFolders (
        val hide_empty_folders: Boolean)

data class ByListener (
        val port: String)

data class ByListener1 (
        val listener_port: String)

data class ByMimeType (
        val show_css: Boolean,
        val show_flash: Boolean,
        val show_html: Boolean,
        val show_images: Boolean,
        val show_other_binary: Boolean,
        val show_other_text: Boolean,
        val show_script: Boolean,
        val show_xml: Boolean)

data class ByRequestType (
        val hide_items_without_responses: Boolean,
        val show_only_in_scope_items: Boolean,
        val show_only_parameterized_requests: Boolean)

data class ByRequestType1 (
        val hide_incoming_messages: Boolean,
        val hide_outgoing_messages: Boolean,
        val show_only_in_scope_items: Boolean)

data class ByRequestType2 (
        val hide_not_found_items: Boolean,
        val show_only_in_scope_items: Boolean,
        val show_only_parameterized_requests: Boolean,
        val show_only_requested_items: Boolean)

data class BySearch (
        val case_sensitive: Boolean,
        val negative_search: Boolean,
        val regex: Boolean,
        val term: String)

data class ByStatusCode (
        val show_2xx: Boolean,
        val show_3xx: Boolean,
        val show_4xx: Boolean,
        val show_5xx: Boolean)

data class Certificate (
        val certificate_file: String,
        val enabled: Boolean,
        val host: String,
        val password: String,
        val type: String)

data class ClientCertificates (
        val certificates: List<Certificate>,
        val use_user_options: Boolean)

data class CollaboratorServer (
        val location: String,
        val poll_over_unencrypted_http: Boolean,
        val polling_location: String,
        val type: String)

data class Connections (
        val hostname_resolution: List<HostnameResolution>,
        val out_of_scope_requests: OutOfScopeRequests,
        val platform_authentication: PlatformAuthentication,
        val socks_proxy: SocksProxy,
        val timeouts: Timeouts,
        val upstream_proxy: UpstreamProxy)

data class CookieJar (
        val monitor_extender: Boolean,
        val monitor_intruder: Boolean,
        val monitor_proxy: Boolean,
        val monitor_repeater: Boolean,
        val monitor_scanner: Boolean,
        val monitor_sequencer: Boolean)

data class Credential (
        val auth_type: String,
        val destination_host: String,
        val password: String,
        val username: String)

data class CustomParameter (
        val case_sensitive: Boolean,
        val end_at_delimiter: String,
        val end_at_fixed_length: Int,
        val end_mode: String,
        val exclude_http_headers: Boolean,
        val extract_mode: String,
        val name: String,
        val regular_expression: String,
        val start_af_offset: Int,
        val start_after_expression: String,
        val start_at_mode: String,
        val url_encoded: Boolean)

data class Exclude (
        val enabled: Boolean,
        val prefix: String)

data class Filter (
        val by_annotation: ByAnnotation,
        val by_file_extension: ByFileExtension,
        val by_folders: ByFolders,
        val by_mime_type: ByMimeType,
        val by_request_type: ByRequestType2,
        val by_search: BySearch,
        val by_status_code: ByStatusCode)

data class HostnameResolution (
        val enabled: Boolean,
        val hostname: String,
        val ip_address: String)

data class Http (
        val redirections: Redirections,
        val status_100_responses: Status100Responses,
        val streaming_responses: StreamingResponses)

data class HttpHistoryDisplayFilter (
        val by_annotation: ByAnnotation,
        val by_file_extension: ByFileExtension,
        val by_listener: ByListener,
        val by_mime_type: ByMimeType,
        val by_request_type: ByRequestType,
        val by_search: BySearch,
        val by_status_code: ByStatusCode)

data class Include (
        val enabled: Boolean,
        val prefix: String)

data class InterceptClientRequests (
        val automatically_fix_missing_or_superfluous_new_lines_at_end_of_request: Boolean,
        val automatically_update_content_length_header_when_the_request_is_edited: Boolean,
        val do_intercept: Boolean,
        val rules: List<Rule1>)

data class InterceptServerResponses (
        val automatically_update_content_length_header_when_the_response_is_edited: Boolean,
        val do_intercept: Boolean,
        val rules: List<Rule2>)

data class InterceptWebSocketsMessages (
        val client_to_server_messages: Boolean,
        val server_to_client_messages: Boolean)

data class Item (
        val accept_response_cookies: Boolean,
        val custom_parameters: List<CustomParameter>,
        val method: String,
        val request: String,
        val request_parameters: List<Any>,
        val response: String,
        val status_code: Int,
        val url: String,
        val use_request_cookies: Boolean)

data class LiveCapture (
        val ignore_abnormal_length_tokens: Boolean,
        val max_length_deviation: Int,
        val num_threads: Int,
        val throttle: Int)

data class Logging (
        val requests: Requests,
        val responses: Responses)

data class Macro (
        val description: String,
        val items: List<Item>,
        val serial_number: Long)

data class Macros (
        val macros: List<Macro>)

data class MatchReplaceRule (
        val comment: String,
        val enabled: Boolean,
        val is_simple_match: Boolean,
        val rule_type: String,
        val string_match: String,
        val string_replace: String)

data class Misc (
        val collaborator_server: CollaboratorServer,
        val logging: Logging,
        val scheduled_tasks: ScheduledTasks)

data class Miscellaneous (
        val disable_logging_to_history_and_site_map: Boolean,
        val disable_out_of_scope_logging_to_history_and_site_map: Boolean,
        val disable_web_interface: Boolean,
        val remove_unsupported_encodings_from_accept_encoding_headers_in_incoming_requests: Boolean,
        val set_connection_close_header_on_requests: Boolean,
        val set_connection_close_header_on_responses: Boolean,
        val strip_proxy_headers_in_incoming_requests: Boolean,
        val strip_sec_websocket_extensions_headers_in_incoming_requests: Boolean,
        val suppress_burp_error_messages_in_browser: Boolean,
        val unpack_gzip_deflate_in_requests: Boolean,
        val unpack_gzip_deflate_in_responses: Boolean,
        val use_http_10_in_requests_to_server: Boolean,
        val use_http_10_in_responses_to_client: Boolean)

data class Negotiation (
        val allow_unsafe_renegotiation: Boolean,
        val automatically_select_compatible_ssl_parameters_on_failure: Boolean,
        val disable_ssl_session_resume: Boolean,
        val enabled_ciphers: List<String>,
        val enabled_protocols: List<String>,
        val use_platform_default_protocols_and_ciphers: Boolean)

data class OutOfScopeRequests (
        val advanced_mode: Boolean,
        val drop_all_out_of_scope: Boolean,
        val exclude: List<Exclude>,
        val include: List<Include>,
        val scope_option: String)

data class PlatformAuthentication (
        val credentials: List<Credential>,
        val do_platform_authentication: Boolean,
        val prompt_on_authentication_failure: Boolean,
        val use_user_options: Boolean)

data class ProjectOptions (
        val connections: Connections,
        val http: Http,
        val misc: Misc,
        val sessions: Sessions,
        val ssl: Ssl)

data class Proxy (
        val http_history_display_filter: HttpHistoryDisplayFilter,
        val intercept_client_requests: InterceptClientRequests,
        val intercept_server_responses: InterceptServerResponses,
        val intercept_web_sockets_messages: InterceptWebSocketsMessages,
        val match_replace_rules: List<MatchReplaceRule>,
        val miscellaneous: Miscellaneous,
        val request_listeners: List<RequestListener>,
        val response_modification: ResponseModification,
        val ssl_pass_through: SslPassThrough,
        val web_sockets_history_display_filter: WebSocketsHistoryDisplayFilter)

data class Redirections (
        val understand_3xx_status_code: Boolean,
        val understand_any_status_code_with_location_header: Boolean,
        val understand_javascript_driven: Boolean,
        val understand_meta_refresh_tag: Boolean,
        val understand_refresh_header: Boolean)

data class Repeater (
        val follow_redirections: String,
        val process_cookies_in_redirections: Boolean,
        val unpack_gzip_deflate: Boolean,
        val update_content_length: Boolean)

data class RequestListener (
        val certificate_mode: String,
        val listen_mode: String,
        val listener_port: Int,
        val running: Boolean)

data class Requests (
        val all_tools: String,
        val extender: String,
        val intruder: String,
        val proxy: String,
        val repeater: String,
        val scanner: String,
        val sequencer: String)

data class ResponseModification (
        val convert_https_links_to_http: Boolean,
        val enable_disabled_form_fields: Boolean,
        val highlight_unhidden_fields: Boolean,
        val remove_all_javascript: Boolean,
        val remove_input_field_length_limits: Boolean,
        val remove_javascript_form_validation: Boolean,
        val remove_object_tags: Boolean,
        val remove_secure_flag_from_cookies: Boolean,
        val unhide_hidden_form_fields: Boolean)

data class Responses (
        val all_tools: String,
        val extender: String,
        val intruder: String,
        val proxy: String,
        val repeater: String,
        val scanner: String,
        val sequencer: String)

data class Root (
        val project_options: ProjectOptions,
        val proxy: Proxy,
        val repeater: Repeater,
        val sequencer: Sequencer,
        val target: Target)

data class Rule (
        val actions: List<Action>,
        val description: String,
        val enabled: Boolean,
        val exclude_from_scope: List<Any>,
        val include_in_scope: List<Any>,
        val named_params: List<Any>,
        val restrict_scope_to_named_params: Boolean,
        val tools_scope: List<String>,
        val url_scope: String,
        val url_scope_advanced_mode: Boolean)

data class Rule1 (
        val boolean_operator: String,
        val enabled: Boolean,
        val match_condition: String,
        val match_relationship: String,
        val match_type: String)

data class Rule2 (
        val boolean_operator: String,
        val enabled: Boolean,
        val match_condition: String,
        val match_relationship: String,
        val match_type: String)

data class Rule3 (
        val enabled: Boolean,
        val host: String,
        val port: String,
        val protocol: String)

data class ScheduledTasks (
        val tasks: List<Task>)

data class Scope (
        val advanced_mode: Boolean,
        val exclude: List<Exclude>,
        val include: List<Include>)

data class Sequencer (
        val live_capture: LiveCapture,
        val token_analysis: TokenAnalysis,
        val token_handling: TokenHandling)

data class Server (
        val auth_type: String,
        val destination_host: String,
        val enabled: Boolean,
        val password: String,
        val proxy_host: String,
        val proxy_port: Int,
        val username: String)

data class SessionHandlingRules (
        val rules: List<Rule>)

data class Sessions (
        val cookie_jar: CookieJar,
        val macros: Macros,
        val session_handling_rules: SessionHandlingRules)

data class SocksProxy (
        val dns_over_socks: Boolean,
        val host: String,
        val password: String,
        val port: Int,
        val use_proxy: Boolean,
        val use_user_options: Boolean,
        val username: String)

data class Ssl (
        val client_certificates: ClientCertificates,
        val negotiation: Negotiation)

data class SslPassThrough (
        val automatically_add_entries_on_client_ssl_negotiation_failure: Boolean,
        val rules: List<Rule3>)

data class Status100Responses (
        val remove_100_continue_responses: Boolean,
        val understand_100_continue_responses: Boolean)

data class StreamingResponses (
        val scope_advanced_mode: Boolean,
        val store: Boolean,
        val strip_chunked_encoding_metadata: Boolean,
        val urls: List<Url>)

data class Target (
        val filter: Filter,
        val scope: Scope)

data class Task (
        val repeat_number: Int,
        val repeat_unit: String,
        val task: String,
        val time: String)

data class Timeouts (
        val domain_name_resolution_timeout: Int,
        val failed_domain_name_resolution_timeout: Int,
        val normal_timeout: Int,
        val open_ended_response_timeout: Int)

data class TokenAnalysis (
        val compression: Boolean,
        val correlation: Boolean,
        val count: Boolean,
        val fips_long_run: Boolean,
        val fips_monobit: Boolean,
        val fips_poker: Boolean,
        val fips_runs: Boolean,
        val spectral: Boolean,
        val transitions: Boolean)

data class TokenHandling (
        val base_64_decode_before_analyzing: Boolean,
        val pad_short_tokens_at: String,
        val pad_with: String)

data class UpstreamProxy (
        val servers: List<Server>,
        val use_user_options: Boolean)

data class Url (
        val enabled: Boolean,
        val prefix: String)

data class WebSocketsHistoryDisplayFilter (
        val by_annotation: ByAnnotation,
        val by_listener: ByListener1,
        val by_request_type: ByRequestType1,
        val by_search: BySearch)

