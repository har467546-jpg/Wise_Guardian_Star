INSERT INTO assets (
    id,
    ip,
    hostname,
    os_name,
    owner,
    criticality,
    status,
    tags,
    metadata_json,
    first_seen_at,
    last_seen_at
) VALUES (
    '11111111-1111-1111-1111-111111111111',
    '10.10.0.10',
    'web-01.lab.local',
    'Ubuntu 22.04',
    'secops',
    'high',
    'online',
    '["prod-like", "web"]'::jsonb,
    '{"environment":"lab","source":"cidr_scan"}'::jsonb,
    NOW() - INTERVAL '2 days',
    NOW()
), (
    '22222222-2222-2222-2222-222222222222',
    '10.10.0.20',
    'redis-01.lab.local',
    'Debian 12',
    'platform',
    'medium',
    'online',
    '["cache"]'::jsonb,
    '{"environment":"lab","source":"cidr_scan"}'::jsonb,
    NOW() - INTERVAL '1 day',
    NOW()
);

INSERT INTO tasks (
    id,
    task_type,
    target_cidr,
    status,
    requested_by,
    parameters,
    summary,
    started_at,
    finished_at
) VALUES (
    '33333333-3333-3333-3333-333333333333',
    'discovery',
    '10.10.0.0/24',
    'completed',
    'admin',
    '{"ports":[22,80,443,3306,6379,8080,8443]}'::jsonb,
    '{"online_hosts":2,"open_services":3}'::jsonb,
    NOW() - INTERVAL '10 minutes',
    NOW() - INTERVAL '8 minutes'
);

INSERT INTO services (
    id,
    asset_id,
    port,
    protocol,
    service_name,
    product,
    version,
    banner,
    state,
    detected_by,
    first_seen_at,
    last_seen_at
) VALUES (
    '44444444-4444-4444-4444-444444444444',
    '11111111-1111-1111-1111-111111111111',
    443,
    'tcp',
    'https',
    'nginx',
    '1.24.0',
    'HTTP/1.1 200 OK\r\nServer: nginx/1.24.0',
    'open',
    'banner',
    NOW() - INTERVAL '2 days',
    NOW()
), (
    '55555555-5555-5555-5555-555555555555',
    '11111111-1111-1111-1111-111111111111',
    22,
    'tcp',
    'ssh',
    'OpenSSH',
    '8.9',
    'SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10',
    'open',
    'banner',
    NOW() - INTERVAL '2 days',
    NOW()
), (
    '66666666-6666-6666-6666-666666666666',
    '22222222-2222-2222-2222-222222222222',
    6379,
    'tcp',
    'redis',
    'Redis',
    '7.0.11',
    '+PONG',
    'open',
    'banner',
    NOW() - INTERVAL '1 day',
    NOW()
);

INSERT INTO scan_results (
    id,
    task_id,
    asset_id,
    ip,
    hostname,
    icmp_alive,
    tcp_alive,
    open_ports,
    services,
    raw_result,
    duration_ms,
    scanned_at
) VALUES (
    '77777777-7777-7777-7777-777777777777',
    '33333333-3333-3333-3333-333333333333',
    '11111111-1111-1111-1111-111111111111',
    '10.10.0.10',
    'web-01.lab.local',
    TRUE,
    TRUE,
    '[22, 443]'::jsonb,
    '[{"port":22,"service":"ssh","version":"8.9"},{"port":443,"service":"https","version":"1.24.0"}]'::jsonb,
    '{"icmp_alive":true,"tcp_alive":true,"probe_methods":["ping","syn"]}'::jsonb,
    834,
    NOW() - INTERVAL '8 minutes'
), (
    '88888888-8888-8888-8888-888888888888',
    '33333333-3333-3333-3333-333333333333',
    '22222222-2222-2222-2222-222222222222',
    '10.10.0.20',
    'redis-01.lab.local',
    TRUE,
    TRUE,
    '[6379]'::jsonb,
    '[{"port":6379,"service":"redis","version":"7.0.11"}]'::jsonb,
    '{"icmp_alive":true,"tcp_alive":true,"probe_methods":["ping","connect"]}'::jsonb,
    512,
    NOW() - INTERVAL '8 minutes'
);

INSERT INTO findings (
    id,
    asset_id,
    service_id,
    task_id,
    rule_key,
    title,
    description,
    severity,
    status,
    confidence,
    evidence,
    first_seen_at,
    last_seen_at
) VALUES (
    '99999999-9999-9999-9999-999999999999',
    '11111111-1111-1111-1111-111111111111',
    '55555555-5555-5555-5555-555555555555',
    '33333333-3333-3333-3333-333333333333',
    'SSH-OLD-VERSION',
    'OpenSSH version is below policy baseline',
    'OpenSSH 8.9 is below the internal baseline 9.3 and should be upgraded.',
    'medium',
    'open',
    92.50,
    '{"service":"ssh","version":"8.9","baseline":"9.3"}'::jsonb,
    NOW() - INTERVAL '8 minutes',
    NOW() - INTERVAL '8 minutes'
), (
    'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa',
    '22222222-2222-2222-2222-222222222222',
    '66666666-6666-6666-6666-666666666666',
    '33333333-3333-3333-3333-333333333333',
    'REDIS-NO-AUTH',
    'Redis may be exposed without authentication',
    'Redis responded to an unauthenticated probe and should be restricted.',
    'high',
    'confirmed',
    98.00,
    '{"banner":"+PONG","port":6379}'::jsonb,
    NOW() - INTERVAL '8 minutes',
    NOW() - INTERVAL '8 minutes'
);
