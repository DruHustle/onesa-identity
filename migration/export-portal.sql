-- Run with psql -XqAt -v ON_ERROR_STOP=1 on a read-only account. Protect the JSON output.
BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY;
SELECT jsonb_build_object(
 'version',1,
 'accounts', coalesce((SELECT jsonb_agg(jsonb_build_object('id',u.id,'email',u.email,
   'status',CASE WHEN u.disabled THEN 'suspended' ELSE 'active' END,'role',u.role)
   ORDER BY u.id) FROM users u),'[]'::jsonb),
 'grants', coalesce((SELECT jsonb_agg(jsonb_build_object('id',user_id,'product',product,
   'role',role,'status',status) ORDER BY user_id,product) FROM identity_product_access),'[]'::jsonb),
 'docs', coalesce((SELECT jsonb_agg(jsonb_build_object('membership_id',m.id,'id',l.user_id,
   'enabled',m.enabled) ORDER BY m.id) FROM engineering_memberships m LEFT JOIN identity_engineering_links l ON l.membership_id=m.id),'[]'::jsonb),
 'registrations', coalesce((SELECT jsonb_agg(jsonb_build_object('id',r.id,'state',r.state,'audience',r.audience,
   'revision',r.revision,'user_id',e.user_id) ORDER BY r.id) FROM access_registrations r LEFT JOIN engineering_enrollment_accounts e ON r.id=e.registration_id),'[]'::jsonb),
 'drone_memberships', coalesce((SELECT jsonb_agg(jsonb_build_object('user_id',user_id,'tenant_id',tenant_id,
   'role',role,'label',label) ORDER BY user_id,tenant_id) FROM identity_drone_memberships),'[]'::jsonb));
COMMIT;
