<?php

// source based on ShareXen by Xenthys


define('USERS', [
	'Mario' => 'change-me',
]);

define('SALT', 'change-me');

define('EXTS', ['png', 'jpe?g', 'gif', 'webm', 'mp4']);

define('NAME_LENGTH', 7);

define('ALLOW_CUSTOM_NAMES', false);

define('ADMINS', []);

define('URL_STRIP_EXTENSION', true);

define('DISCORD_WEBHOOK_URL', '');

define('DISCORD_LOG_ERRORS', true);

define('DISCORD_PREVENT_EMBED', true);

define('KEYSPACE', 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789');

define('ALLOWED_CHARACTERS', '-_');

define('MAX_ITERATIONS', 10);

define('ADMIN_IGNORE_KEYSPACE', false);

define('MIME_TYPE_REGEX', '/^(image|video)\//');


function check_constants()
{
	if (!defined('USERS') || gettype(USERS) !== 'array')
	{
		error_die($data, 500, 'invalid_server_configuration',
			'Missing or invalid USERS constant, must be an array.');
	}

	if (!defined('EXTS') || gettype(EXTS) !== 'array')
	{
		error_die($data, 500, 'invalid_server_configuration',
			'Missing or invalid EXTS constant, must be an array.');
	}

	if (!defined('SALT'))
	{
		define('SALT', '');
	}
	if (gettype(SALT) !== 'string')
	{
		error_die($data, 500, 'invalid_server_configuration',
			'Invalid SALT constant, must be a string.');
	}

	if (!defined('NAME_LENGTH'))
	{
		define('NAME_LENGTH', 7);
	}
	if (gettype(NAME_LENGTH) !== 'integer')
	{
		error_die($data, 500, 'invalid_server_configuration',
			'Invalid NAME_LENGTH constant, must be an integer.');
	}

	if (!defined('ALLOW_CUSTOM_NAMES'))
	{
		define('ALLOW_CUSTOM_NAMES', false);
	}
	if (gettype(ALLOW_CUSTOM_NAMES) !== 'boolean')
	{
		error_die($data, 500, 'invalid_server_configuration',
			'Invalid ALLOW_CUSTOM_NAMES constant, must be a boolean.');
	}

	if (!defined('ADMINS'))
	{
		define('ADMINS', []);
	}
	if (gettype(ADMINS) !== 'array')
	{
		error_die($data, 500, 'invalid_server_configuration',
			'Invalid ADMINS constant, must be an array.');
	}

	if (!defined('URL_STRIP_EXTENSION'))
	{
		define('URL_STRIP_EXTENSION', false);
	}
	if (gettype(URL_STRIP_EXTENSION) !== 'boolean')
	{
		error_die($data, 500, 'invalid_server_configuration',
			'Invalid URL_STRIP_EXTENSION constant, must be a boolean.');
	}

	if (!defined('DISCORD_WEBHOOK_URL'))
	{
		define('DISCORD_WEBHOOK_URL', '');
	}
	if (gettype(DISCORD_WEBHOOK_URL) !== 'string')
	{
		error_die($data, 500, 'invalid_server_configuration',
			'Invalid DISCORD_WEBHOOK_URL constant, must be a string.');
	}

	if (!defined('DISCORD_LOG_ERRORS'))
	{
		define('DISCORD_LOG_ERRORS', true);
	}
	if (gettype(DISCORD_LOG_ERRORS) !== 'boolean')
	{
		error_die($data, 500, 'invalid_server_configuration',
			'Invalid DISCORD_LOG_ERRORS constant, must be a boolean.');
	}

	if (!defined('DISCORD_PREVENT_EMBED'))
	{
		define('DISCORD_PREVENT_EMBED', true);
	}
	if (gettype(DISCORD_PREVENT_EMBED) !== 'boolean')
	{
		error_die($data, 500, 'invalid_server_configuration',
			'Invalid DISCORD_PREVENT_EMBED constant, must be a boolean.');
	}

	if (!defined('KEYSPACE'))
	{
		define('KEYSPACE', 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789');
	}
	if (gettype(KEYSPACE) !== 'string')
	{
		error_die($data, 500, 'invalid_server_configuration',
			'Invalid KEYSPACE constant, must be a string.');
	}

	if (!defined('ALLOWED_CHARACTERS'))
	{
		define('ALLOWED_CHARACTERS', '-_');
	}
	if (gettype(ALLOWED_CHARACTERS) !== 'string')
	{
		error_die($data, 500, 'invalid_server_configuration',
			'Invalid ALLOWED_CHARACTERS constant, must be a string.');
	}

	if (!defined('MAX_ITERATIONS'))
	{
		define('MAX_ITERATIONS', 10);
	}
	if (gettype(MAX_ITERATIONS) !== 'integer')
	{
		error_die($data, 500, 'invalid_server_configuration',
			'Invalid MAX_ITERATIONS constant, must be an integer.');
	}

	if (!defined('ADMIN_IGNORE_KEYSPACE'))
	{
		define('ADMIN_IGNORE_KEYSPACE', false);
	}
	if (gettype(ADMIN_IGNORE_KEYSPACE) !== 'boolean')
	{
		error_die($data, 500, 'invalid_server_configuration',
			'Invalid ADMIN_IGNORE_KEYSPACE constant, must be a boolean.');
	}

	if (!defined('MIME_TYPE_REGEX'))
	{
		define('MIME_TYPE_REGEX', '/^(image|video)\//');
	}
	if (gettype(MIME_TYPE_REGEX) !== 'string')
	{
		error_die($data, 500, 'invalid_server_configuration',
			'Invalid MIME_TYPE_REGEX constant, must be a string.');
	}
}

function get_parameter($field)
{
	return @$_GET[$field] ?: @$_POST[$field];
}

function send_to_discord($msg)
{
	$c['content'] = "`[".date('H:i:s')."]` $msg";

	$opts['http'] = [
		'method' => 'POST',
		'header' => "Content-Type: application/json\r\n".
			"User-Agent: ShareXen/".VERSION." (+".SOURCE.")\r\n",
		'content' => json_encode($c)
	];

	$ctx = stream_context_create($opts);
	return @file_get_contents(DISCORD_WEBHOOK_URL, false, $ctx) === '';
}

function log_request(&$data)
{
	global $endpoints;

	$url = @$data['url'];
	$user = @$data['username'];
	$endpoint = @$data['endpoint'];

	$msg = $user ? "Authenticated user $user" : 'Unauthenticated user';

	$status = @$data['error'] ?: $data['status'];
	$msg .= " got a $data[http_code] ($status) reponse ".
		"code, after calling the \"$endpoint\" endpoint.";

	$discord_logging = DISCORD_WEBHOOK_URL ? true : false;
	$discord_header = @$endpoints[$endpoint] ?: "\u{2705}";

	if ($status !== 'success')
	{
		if (DISCORD_LOG_ERRORS)
		{
			$discord_header = "\u{26A0}";
		}
		else
		{
			$discord_logging = false;
		}
	}

	if ($url)
	{
		$msg .= " File URL: $url";
		if (isset($data['old_name']))
		{
			$msg .= " (old name: $data[old_name])";
		}
	}
	elseif (isset($data['filename']))
	{
		$msg .= " Target file: $data[filename]";
	}

	error_log("ShareXen v".VERSION.": $msg");

	if ($discord_logging)
	{
		if (DISCORD_PREVENT_EMBED && $url)
		{
			$msg = str_replace($url, "<$url>", $msg);
		}

		if (!send_to_discord("$discord_header $msg"))
		{
			error_log('ShareXen Error: cannot send to Discord.');
		}
	}
}

function end_request(&$data, $code = 200, $status = 'success')
{
	$data['http_code'] = $code;
	$data['status'] = $status;

	$data['execution_time'] = microtime(true) - $_SERVER['REQUEST_TIME_FLOAT'];

	ob_start();

	http_response_code($code);

	header('Content-Type: application/json; charset=utf-8');
	header('Content-Encoding: none');

	echo(json_encode($data));

	header('Content-Length: '.ob_get_length());
	header('Connection: close');

	ob_end_flush();
	ob_flush();
	flush();

	log_request($data);

	die();
}

function error_die(&$data, $code, $reason = 'unknown_error', $debug = '')
{
	$data['error'] = $reason;

	if ($debug)
	{
		$data['debug'] = $debug;
	}

	end_request($data, $code, 'error');
}

function perform_auth(&$data)
{
	if (!isset($_POST['token']))
	{
		return;
	}

	$token = $_POST['token'];

	if (!$token || $token === 'change-me')
	{
		error_die($data, 403, 'invalid_credentials');
	}

	$user = array_search($token, USERS);

	if ($user === false)
	{
		error_die($data, 403, 'invalid_credentials');
	}

	$data['username'] = strval($user);
}

function retrieve_key($name)
{
	if (!SALT || SALT === 'change-me')
	{
		return false;
	}

	$filehash = hash_file('sha256', $name);
	return hash('sha256', SALT.$filehash.$name);
}

function enforce_auth(&$data)
{
	if (!isset($data['username']))
	{
		error_die($data, 401, 'unauthenticated_request');
	}
}

function user_is_admin(&$data)
{
	if (!isset($data['username']))
	{
		return false;
	}

	return array_search($data['username'], ADMINS) !== false;
}

function random_str($length = NAME_LENGTH, $keyspace = KEYSPACE)
{
	$result = '';
	$max = strlen($keyspace) - 1;

	for ($i = 0; $i < $length; $i++) {
		$result .= $keyspace[random_int(0, $max)];
	}

	return $result;
}

function generate_all_urls(&$data, $deletion = true)
{
	$protocol = get_parameter('protocol');

	if (!$protocol)
	{
		$https = $_SERVER['HTTPS'];
		$protocol = 'http'.($https?'s':'');
	}

	$protocol = $protocol.'://';

	$domain = get_parameter('domain');
	$host = $_SERVER['HTTP_HOST'];
	$domain = $domain ?: $host;

	$script = $_SERVER['SCRIPT_NAME'];
	$sub = rtrim(dirname($script), '/').'/';

	$name = $data['filename'];

	$data['url'] = "$protocol$domain$sub$name";

	if (URL_STRIP_EXTENSION)
	{
		$data['url'] = preg_replace('/\.[^.]+$/', '', $data['url']);
	}

	if (!$deletion)
	{
		return;
	}

	$key = retrieve_key($name);

	if ($key)
	{
		$data['key'] = $key;

		$data['deletion_url'] = "$protocol$host".
			"$_SERVER[REQUEST_URI]?endpoint=delete".
			"&key=$key&filename=$name";
	}
}

function check_filename(&$data, $name)
{
	if (!$name)
	{
		return false;
	}

	$name = strval($name);

	$chars = preg_quote(KEYSPACE.ALLOWED_CHARACTERS, '/');
	$regex = "/^[$chars]+\.(".implode('|', EXTS).")$/";

	if (ADMIN_IGNORE_KEYSPACE && user_is_admin($data))
	{
		$regex = '/^.+\.('.implode('|', EXTS).')$/';
	}

	return preg_match($regex, $name);
}

function get_custom_filename(&$data, $check = true, $field = 'filename')
{
	if ($check && !ALLOW_CUSTOM_NAMES && !user_is_admin($data))
	{
		return false;
	}

	$filename = get_parameter($field);

	if (check_filename($data, $filename))
	{
		if ($check && file_exists($filename))
		{
			error_die($data, 403, 'file_already_exists');
		}

		return $filename;
	}
	elseif (isset($filename))
	{
		error_die($data, 403, 'forbidden_filename');
	}

	return false;
}

function ensure_file_exists(&$data, $name, $field = 'filename')
{
	if (!$name)
	{
		error_die($data, 400, 'missing_filename');
	}

	$data[$field] = $name;

	if (!file_exists($name))
	{
		error_die($data, 404, 'file_not_found');
	}
}

function ensure_file_access(&$data, $name, $restricted = true)
{
	$check_hash = !$restricted;

	if ($restricted) {
		$check_hash = ALLOW_CUSTOM_NAMES;
	}

	if (!file_exists($name) && $check_hash)
	{
		return;
	}

	if (user_is_admin($data))
	{
		$data['method'] = 'admin_user';
	}
	elseif ($check_hash)
	{
		$key = get_parameter('key');

		if (isset($key))
		{
			$real_key = retrieve_key($name);

			if (!$real_key || $key !== $real_key)
			{
				error_die($data, 403, 'invalid_key');
			}

			$data['method'] = 'key';
		}
	}

	if (!isset($data['method']))
	{
		error_die($data, 403, 'missing_permissions');
	}
}

function upload_endpoint(&$data)
{
	enforce_auth($data);

	$file = $_FILES['image'];

	if (!isset($file))
	{
		error_die($data, 400, 'missing_file');
	}

	$regex = '/^('.implode('|', EXTS).')$/';
	$ext = strtolower(pathinfo($file['name'], PATHINFO_EXTENSION));

	if (!isset($ext) || !preg_match($regex, $ext))
	{
		error_die($data, 415, 'invalid_file_extension');
	}

	$ext = ".$ext";

	$mime = mime_content_type($file['tmp_name']);
	if (!preg_match(MIME_TYPE_REGEX, $mime))
	{
		error_die($data, 415, 'invalid_file_mime_type');
	}

	$name = get_custom_filename($data);

	if (!$name)
	{
		for ($i = 1; $i <= MAX_ITERATIONS; $i++)
		{
			$name = random_str().$ext;

			if (!file_exists($name))
			{
				$data['iteration_count'] = $i;
				break;
			}

			error_log("ShareXen Collision (iteration ".
				"#$i): File \"$name\" already exists.");

			if ($i == MAX_ITERATIONS)
			{
				error_die($data, 500, 'cannot_generate_unique_filename');
			}
		}
	}

	if (!move_uploaded_file($file['tmp_name'], $name))
	{
		error_die($data, 500, 'upload_failed');
	}

	$data['filename'] = $name;

	generate_all_urls($data);
}

function delete_endpoint(&$data)
{
	$name = get_custom_filename($data, false);

	ensure_file_exists($data, $name);
	ensure_file_access($data, $name, false);

	if (!unlink($name))
	{
		error_die($data, 500, 'delete_failed');
	}
}

function rename_endpoint(&$data)
{
	enforce_auth($data);

	if (!ALLOW_CUSTOM_NAMES && !user_is_admin($data))
	{
		error_die($data, 403, 'missing_permissions');
	}

	$old_name = get_custom_filename($data, false);

	ensure_file_exists($data, $old_name, 'old_name');
	ensure_file_access($data, $old_name);

	$new_name = get_custom_filename($data, true, 'new_name');

	if (!$new_name)
	{
		error_die($data, 400, 'missing_new_name');
	}

	if (!rename($old_name, $new_name))
	{
		error_die($data, 500, 'rename_failed');
	}

	$data['filename'] = $new_name;

	generate_all_urls($data);
}

function info_endpoint(&$data)
{
	enforce_auth($data);

	$data['is_admin'] = user_is_admin($data);

	$name = get_custom_filename($data, false);

	if ($name)
	{
		$data['file_exists'] = file_exists($name);

		if ($data['file_exists'])
		{
			$data['filename'] = $name;
			$data['filesize'] = filesize($name);
			$data['uploaded_at'] = filemtime($name);

			generate_all_urls($data, $data['is_admin']);
		}
	}
	else
	{
		global $keys;
		$data['endpoints'] = $keys;

		$data['keyspace'] = KEYSPACE;
		$data['name_length'] = NAME_LENGTH;
		$data['max_iterations'] = MAX_ITERATIONS;

		$data['allowed_extensions'] = EXTS;
		$data['allowed_characters'] = ALLOWED_CHARACTERS;
		$data['custom_names'] = ALLOW_CUSTOM_NAMES;

		$pattern = '*.{'.implode(',', EXTS).'}';
		$files = glob($pattern, GLOB_BRACE) ?: [];
		$data['files_count'] = count($files);

		if (!$data['is_admin'])
		{
			return;
		}

		$data['files'] = $files;
		$data['users'] = array_map(strval, array_keys(USERS));
		$data['admins'] = array_map(strval, ADMINS);

		$data['can_use_webhook'] = @ini_get('allow_url_fopen') === '1';
		$data['discord_webhook'] = DISCORD_WEBHOOK_URL ? true : false;
	}
}

define('VERSION', '2.3.1');
define('SOURCE', 'https://github.com/Xenthys/ShareXen');

$data = [
	'api_version' => VERSION,
	'api_source' => SOURCE
];

$endpoints = [
	'upload' => "\u{1F517}",
	'delete' => "\u{1F5D1}",
	'rename' => "\u{1F4DD}",
	'info' => "\u{2139}"
];

$keys = array_keys($endpoints);
$endpoint = get_parameter('endpoint');
$data['endpoint'] = $endpoint ?: 'unknown';

check_constants();
perform_auth($data);

if (!in_array($endpoint, $keys))
{
	error_die($data, 404, 'unknown_endpoint');
}

($endpoint.'_endpoint')($data);

end_request($data);
