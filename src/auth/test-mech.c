/* Copyright (c) 2020 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "auth.h"
#include "array.h"
#include "str.h"
#include "auth-common.h"
#include "auth-request.h"
#include "auth-request-handler-private.h"
#include "auth-settings.h"
#include "otp.h"
#include "mech-otp-skey-common.h"
#include "settings-parser.h"
#include "password-scheme.h"
#include "test-common.h"
#include "test-auth.h"
#include "auth-token.h"

#include <unistd.h>
#include <time.h>

#define UCHAR_LEN(str) (const unsigned char *)(str), sizeof(str)-1

extern const struct mech_module mech_oauthbearer;
extern const struct mech_module mech_otp;
extern const struct mech_module mech_ntlm;
extern const struct mech_module mech_rpa;

static struct auth_settings set;
static struct mechanisms_register *mech_reg;

struct test_case {
	const struct mech_module *mech;
	const unsigned char *in;
	size_t len;
	const char *username;
	const char *expect_error;
	bool success;
	bool set_username_before_test;
	bool set_cert_username;
};

static void
verify_plain_continue_mock_callback(struct auth_request *request,
				    verify_plain_callback_t *callback)
{
	request->passdb_success = TRUE;
	callback(PASSDB_RESULT_OK, request);
}

static void
request_handler_reply_mock_callback(struct auth_request *request,
				    enum auth_client_result result,
				    const void *auth_reply ATTR_UNUSED,
				    size_t reply_size ATTR_UNUSED)
{
	request->failed = result != AUTH_CLIENT_RESULT_SUCCESS;

	if (request->passdb_result == PASSDB_RESULT_OK)
		request->failed = FALSE;
	else if (request->mech == &mech_otp) {
		if (null_strcmp(request->user, "otp_phase_2") == 0)
			request->failed = FALSE;
	} else if (request->mech == &mech_oauthbearer) {
	}
};

static void
request_handler_reply_continue_mock_callback(struct auth_request *request,
					     const void *reply,
					     size_t reply_size)
{
	request->context = p_strndup(request->pool, reply, reply_size);
}

static void
auth_client_request_mock_callback(const char *reply ATTR_UNUSED,
				  struct auth_client_connection *conn ATTR_UNUSED)
{
}

static void test_mechs_init(void)
{
	const char *const services[] = {NULL};
	process_start_time = time(NULL);

	/* Copy default settings */
	set = *(struct auth_settings *) auth_setting_parser_info.defaults;
	global_auth_settings = &set;
	global_auth_settings->base_dir = ".";
	memset((&set)->username_chars_map, 1, sizeof((&set)->username_chars_map));
	set.username_format = "";

	t_array_init(&set.passdbs, 2);
	struct auth_passdb_settings *mock_set = t_new(struct auth_passdb_settings, 1);
	*mock_set = mock_passdb_set;
	array_push_back(&set.passdbs, &mock_set);
	mock_set = t_new(struct auth_passdb_settings, 1);
	*mock_set = mock_passdb_set;
	mock_set->master = TRUE;
	array_push_back(&set.passdbs, &mock_set);
	t_array_init(&set.userdbs, 1);

	/* Disable stats */
	set.stats = FALSE;

	/* For tests of digest-md5. */
	set.realms_arr = t_strsplit_spaces("example.com ", " ");
	/* For tests of mech-anonymous. */
	set.anonymous_username = "anonuser";

	mech_init(global_auth_settings);
	mech_reg = mech_register_init(global_auth_settings);
	passdbs_init();
	userdbs_init();
	passdb_mock_mod_init();
	password_schemes_init();

	auths_preinit(&set, pool_datastack_create(), mech_reg, services);
	auths_init();
	auth_token_init();
}


static void test_rpa(void)
{
	static struct auth_request_handler handler = {
		.callback = auth_client_request_mock_callback,
		.reply_callback = request_handler_reply_mock_callback,
		.reply_continue_callback = request_handler_reply_continue_mock_callback,
		.verify_plain_continue_callback = verify_plain_continue_mock_callback,
	};

	const struct mech_module *mech = &mech_rpa;
	test_begin("test rpa");
	struct auth_request *req = mech->auth_new();
	global_auth_settings->realms_arr = t_strsplit("example.com", " ");
	req->set = global_auth_settings;
	req->service = "login";
	req->handler = &handler;
	//req->mech_event = event_create(NULL);
	//req->event = event_create(NULL);
	req->mech = mech;
	req->state = AUTH_REQUEST_STATE_MECH_CONTINUE;
	auth_request_state_count[AUTH_REQUEST_STATE_MECH_CONTINUE] = 1;
	mech->auth_initial(req, UCHAR_LEN("\x60\x11\x06\x09\x60\x86\x48\x01\x86\xf8\x73\x01\x01\x01\x00\x04\x00\x00\x01"));
	mech->auth_continue(req, UCHAR_LEN("\x60\x11\x06\x09\x60\x86\x48\x01\x86\xf8\x73\x01\x01\x00\x03A@A\x00"));
	test_assert(req->failed == TRUE);
	test_assert(req->passdb_success == FALSE);
	//event_unref(&req->mech_event);
	//event_unref(&req->event);
	mech->auth_free(req);
	test_end();
}

static void test_ntlm(void)
{
	static struct auth_request_handler handler = {
		.callback = auth_client_request_mock_callback,
		.reply_callback = request_handler_reply_mock_callback,
		.reply_continue_callback = request_handler_reply_continue_mock_callback,
		.verify_plain_continue_callback = verify_plain_continue_mock_callback,
	};

	const struct mech_module *mech = &mech_ntlm;
	test_begin("test ntlm");
	struct auth_request *req = mech->auth_new();
	global_auth_settings->realms_arr = t_strsplit("example.com", " ");
	req->set = global_auth_settings;
	req->service = "login";
	req->handler = &handler;
	//req->mech_event = event_create(NULL);
	//req->event = event_create(NULL);
	req->mech = mech;
	req->state = AUTH_REQUEST_STATE_MECH_CONTINUE;
	auth_request_state_count[AUTH_REQUEST_STATE_MECH_CONTINUE] = 1;
	mech->auth_initial(req, UCHAR_LEN("NTLMSSP\x00\x01\x00\x00\x00\x00\x02\x00\x00""AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"));
	mech->auth_continue(req, UCHAR_LEN("NTLMSSP\x00\x03\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00""AA\x00\x00\x41\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00""orange""\x00"));
	test_assert(req->failed == TRUE);
	test_assert(req->passdb_success == FALSE);
	//event_unref(&req->mech_event);
	//event_unref(&req->event);
	mech->auth_free(req);
	test_end();
}

int main(void)
{
	static void (*const test_functions[])(void) = {
		test_rpa,
		test_ntlm,
		NULL
	};
	lib_init();
	test_mechs_init();
	int ret = test_run(test_functions);
	mech_register_deinit(&mech_reg);
	return ret;
}
