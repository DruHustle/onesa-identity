-- Run with psql -XqAt -v ON_ERROR_STOP=1 on a read-only account. Protect the JSON output.
BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY;
SELECT jsonb_build_object(
 'version',1,
 'accounts', coalesce((SELECT jsonb_agg(jsonb_build_object('id',u.id,'email',u.email,
   'status',CASE WHEN u.disabled THEN 'suspended' ELSE 'active' END,'role',u.role,'created_at',u.created_at,'display_name',p.display_name,
   'email_verified_at',p.email_verified_at)
   ORDER BY u.id) FROM users u LEFT JOIN identity_profiles p ON p.user_id=u.id),'[]'::jsonb),
 'grants', coalesce((SELECT jsonb_agg(jsonb_build_object('id',user_id,'product',product,
   'role',role,'status',status,'revision',revision,'reviewed_by',reviewed_by,'updated_at',updated_at) ORDER BY user_id,product) FROM identity_product_access),'[]'::jsonb),
 'docs', coalesce((SELECT jsonb_agg(jsonb_build_object('membership_id',m.id,'id',l.user_id,
   'enabled',m.enabled,'access_policy_evidence',m.access_policy_evidence,
   'approved_by',m.approved_by,'approved_at',m.approved_at,'revision',m.revision,'linked_at',l.linked_at) ORDER BY m.id) FROM engineering_memberships m LEFT JOIN identity_engineering_links l ON l.membership_id=m.id),'[]'::jsonb),
 'registrations', coalesce((SELECT jsonb_agg(jsonb_build_object('id',r.id,'state',r.state,'audience',r.audience,
   'revision',r.revision,'user_id',e.user_id,'email',r.email,'display_name',r.display_name,
   'email_verified_at',r.email_verified_at,'reviewed_by',r.reviewed_by,'review_note',r.review_note,
   'created_at',r.created_at,'updated_at',r.updated_at) ORDER BY r.id) FROM access_registrations r LEFT JOIN engineering_enrollment_accounts e ON r.id=e.registration_id),'[]'::jsonb),
 'drone_memberships', coalesce((SELECT jsonb_agg(jsonb_build_object('user_id',user_id,'tenant_id',tenant_id,
   'role',role,'label',label) ORDER BY user_id,tenant_id) FROM identity_drone_memberships),'[]'::jsonb));
COMMIT;
