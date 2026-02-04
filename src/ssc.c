ssc_session_t *ssc_session_ref(ssc_session_t *self) {
    self->refcount++;
    return self;
}

void ssc_session_unref(ssc_session_t *self) {
    if (self->refcount > 0)
        self->refcount--;
}

void ssc_conn_set_closing(uv_loop_t *loop, ssc_conn_t *conn, uv_check_cb check_cb) {
    uv_read_stop((uv_stream_t*)conn);
    conn->stage = SSC_CONN_STAGE_CLOSING;
    uv_check_init(loop, &conn->check_handle);
    uv_handle_set_data((uv_handle_t*)&conn->check_handle, conn);
    uv_check_start(&conn->check_handle, check_cb);
}
