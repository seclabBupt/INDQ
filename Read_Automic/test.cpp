#include <infiniband/verbs.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define BUFFER_SIZE 1024

int main() {
    struct ibv_device **dev_list;
    struct ibv_device *dev;
    struct ibv_context *ctx;
    struct ibv_pd *pd;
    struct ibv_mr *mr;
    struct ibv_cq *cq;
    struct ibv_qp *qp;
    struct ibv_qp_init_attr qp_init_attr;
    struct ibv_qp_attr qp_attr;
    struct ibv_port_attr port_attr;
    union ibv_gid gid;
    struct ibv_sge sge;
    struct ibv_send_wr wr, *bad_wr;
    char *buffer;
    int ret;

    // Get the list of RDMA devices
    dev_list = ibv_get_device_list(NULL);
    if (!dev_list) {
        fprintf(stderr, "Failed to get RDMA devices list\n");
        return 1;
    }

    // Open the first device (assuming there's at least one device)
    dev = dev_list[0];
    ctx = ibv_open_device(dev);
    if (!ctx) {
        fprintf(stderr, "Failed to open device\n");
        ibv_free_device_list(dev_list);
        return 1;
    }

    // Allocate a protection domain
    pd = ibv_alloc_pd(ctx);
    if (!pd) {
        fprintf(stderr, "Failed to allocate protection domain\n");
        ibv_close_device(ctx);
        ibv_free_device_list(dev_list);
        return 1;
    }

    // Allocate a buffer and register it
    buffer = (char *)malloc(BUFFER_SIZE);
    mr = ibv_reg_mr(pd, buffer, BUFFER_SIZE, IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_READ | IBV_ACCESS_REMOTE_WRITE);
    if (!mr) {
        fprintf(stderr, "Failed to register memory region\n");
        free(buffer);
        ibv_dealloc_pd(pd);
        ibv_close_device(ctx);
        ibv_free_device_list(dev_list);
        return 1;
    }

    // Create a completion queue
    cq = ibv_create_cq(ctx, 10, NULL, NULL, 0);
    if (!cq) {
        fprintf(stderr, "Failed to create completion queue\n");
        ibv_dereg_mr(mr);
        free(buffer);
        ibv_dealloc_pd(pd);
        ibv_close_device(ctx);
        ibv_free_device_list(dev_list);
        return 1;
    }

    // Initialize the QP attributes
    memset(&qp_init_attr, 0, sizeof(qp_init_attr));
    qp_init_attr.send_cq = cq;
    qp_init_attr.recv_cq = cq;
    qp_init_attr.cap.max_send_wr = 10;
    qp_init_attr.cap.max_recv_wr = 10;
    qp_init_attr.cap.max_send_sge = 1;
    qp_init_attr.cap.max_recv_sge = 1;
    qp_init_attr.qp_type = IBV_QPT_RC;

    // Create the QP
    qp = ibv_create_qp(pd, &qp_init_attr);
    if (!qp) {
        fprintf(stderr, "Failed to create QP\n");
        ibv_destroy_cq(cq);
        ibv_dereg_mr(mr);
        free(buffer);
        ibv_dealloc_pd(pd);
        ibv_close_device(ctx);
        ibv_free_device_list(dev_list);
        return 1;
    }

    // Query port attributes
    ret = ibv_query_port(ctx, 1, &port_attr);
    if (ret) {
        fprintf(stderr, "Failed to query port attributes\n");
        ibv_destroy_qp(qp);
        ibv_destroy_cq(cq);
        ibv_dereg_mr(mr);
        free(buffer);
        ibv_dealloc_pd(pd);
        ibv_close_device(ctx);
        ibv_free_device_list(dev_list);
        return 1;
    }
    ret = ibv_query_gid(ctx, 1, 0, &gid);
	if (ret) {
        fprintf(stderr, "Failed to query gid\n");
        ibv_destroy_qp(qp);
        ibv_destroy_cq(cq);
        ibv_dereg_mr(mr);
        free(buffer);
        ibv_dealloc_pd(pd);
        ibv_close_device(ctx);
        ibv_free_device_list(dev_list);
        return 1;
    }

    // Move the QP to INIT state
    memset(&qp_attr, 0, sizeof(qp_attr));
    qp_attr.qp_state = IBV_QPS_INIT;
    qp_attr.pkey_index = 0;
    qp_attr.port_num = 1;
    qp_attr.qp_access_flags = IBV_ACCESS_REMOTE_READ | IBV_ACCESS_REMOTE_WRITE | IBV_ACCESS_LOCAL_WRITE;

    ret = ibv_modify_qp(qp, &qp_attr, IBV_QP_STATE | IBV_QP_PKEY_INDEX | IBV_QP_PORT | IBV_QP_ACCESS_FLAGS);
    if (ret) {
        fprintf(stderr, "Failed to modify QP to INIT state\n");
        ibv_destroy_qp(qp);
        ibv_destroy_cq(cq);
        ibv_dereg_mr(mr);
        free(buffer);
        ibv_dealloc_pd(pd);
        ibv_close_device(ctx);
        ibv_free_device_list(dev_list);
        return 1;
    }
    if (ibv_query_qp(qp, &qp_attr, IBV_QP_ACCESS_FLAGS, &qp_init_attr))
	{
		printf("ibv_query_qp");
	}
	printf("init_attr.qp_access_flags : %d", qp_attr.qp_access_flags);

    // Move the QP to RTR state
    memset(&qp_attr, 0, sizeof(qp_attr));
    qp_attr.qp_state = IBV_QPS_RTR;
    qp_attr.path_mtu = IBV_MTU_1024;
    qp_attr.dest_qp_num = qp->qp_num;
    qp_attr.rq_psn = 0;
    qp_attr.max_dest_rd_atomic = 1;
    qp_attr.min_rnr_timer = 12;
    qp_attr.ah_attr.is_global = 1;
    qp_attr.ah_attr.dlid = port_attr.lid;
    qp_attr.ah_attr.grh.dgid = gid;
    qp_attr.ah_attr.sl = 0;
    qp_attr.ah_attr.grh.flow_label = 0;
    qp_attr.ah_attr.grh.hop_limit = 1;
    qp_attr.ah_attr.grh.sgid_index = 0; // 本地GID索引，需根据实际情况设置
    qp_attr.ah_attr.grh.traffic_class = 0;
    qp_attr.ah_attr.src_path_bits = 0;
    qp_attr.ah_attr.port_num = 1;

    ret = ibv_modify_qp(qp, &qp_attr, IBV_QP_STATE | IBV_QP_AV | IBV_QP_PATH_MTU | IBV_QP_DEST_QPN | IBV_QP_RQ_PSN | IBV_QP_MAX_DEST_RD_ATOMIC | IBV_QP_MIN_RNR_TIMER);
    if (ret) {
        fprintf(stderr, "Failed to modify QP to RTR state\n");
        ibv_destroy_qp(qp);
        ibv_destroy_cq(cq);
        ibv_dereg_mr(mr);
        free(buffer);
        ibv_dealloc_pd(pd);
        ibv_close_device(ctx);
        ibv_free_device_list(dev_list);
        return 1;
    }
    if (ibv_query_qp(qp, &qp_attr, IBV_QP_ACCESS_FLAGS, &qp_init_attr))
	{
		printf("ibv_query_qp");
	}
	printf("rtr_attr.qp_access_flags : %d", qp_attr.qp_access_flags);

    // Move the QP to RTS state
    memset(&qp_attr, 0, sizeof(qp_attr));
    qp_attr.qp_state = IBV_QPS_RTS;
    qp_attr.timeout = 14;
    qp_attr.retry_cnt = 7;
    qp_attr.rnr_retry = 7; // infinite retry
    qp_attr.sq_psn = 0;
    qp_attr.max_rd_atomic = 1;

    ret = ibv_modify_qp(qp, &qp_attr, IBV_QP_STATE | IBV_QP_TIMEOUT | IBV_QP_RETRY_CNT | IBV_QP_RNR_RETRY | IBV_QP_SQ_PSN | IBV_QP_MAX_QP_RD_ATOMIC);
    if (ret) {
        fprintf(stderr, "Failed to modify QP to RTS state\n");
        ibv_destroy_qp(qp);
        ibv_destroy_cq(cq);
        ibv_dereg_mr(mr);
        free(buffer);
        ibv_dealloc_pd(pd);
        ibv_close_device(ctx);
        ibv_free_device_list(dev_list);
        return 1;
    }
    if (ibv_query_qp(qp, &qp_attr, IBV_QP_ACCESS_FLAGS, &qp_init_attr))
	{
		printf("ibv_query_qp");
	}
	printf("rts_attr.qp_access_flags : %d", qp_attr.qp_access_flags);

    // Perform RDMA READ
    memset(&sge, 0, sizeof(sge));
    sge.addr = (uintptr_t)buffer;
    sge.length = BUFFER_SIZE;
    sge.lkey = mr->lkey;

    memset(&wr, 0, sizeof(wr));
    wr.wr_id = 0;
    wr.sg_list = &sge;
    wr.num_sge = 1;
    wr.opcode = IBV_WR_RDMA_READ;
    wr.send_flags = IBV_SEND_SIGNALED;
    wr.wr.rdma.remote_addr = (uintptr_t)buffer;
    wr.wr.rdma.rkey = mr->rkey;

    ret = ibv_post_send(qp, &wr, &bad_wr);
    if (ret) {
        fprintf(stderr, "Failed to post send request\n");
        ibv_destroy_qp(qp);
        ibv_destroy_cq(cq);
        ibv_dereg_mr(mr);
        free(buffer);
        ibv_dealloc_pd(pd);
        ibv_close_device(ctx);
        ibv_free_device_list(dev_list);
        return 1;
    }

    // Wait for completion
    struct ibv_wc wc;
    while ((ret = ibv_poll_cq(cq, 1, &wc)) == 0) {
        // Poll until we get a completion
    }

    if (ret < 0) {
        fprintf(stderr, "Failed to poll completion\n");
        ibv_destroy_qp(qp);
        ibv_destroy_cq(cq);
        ibv_dereg_mr(mr);
        free(buffer);
        ibv_dealloc_pd(pd);
        ibv_close_device(ctx);
        ibv_free_device_list(dev_list);
        return 1;
    }

    if (wc.status != IBV_WC_SUCCESS) {
        fprintf(stderr, "Completion with error, status: %s\n", ibv_wc_status_str(wc.status));
        ibv_destroy_qp(qp);
        ibv_destroy_cq(cq);
        ibv_dereg_mr(mr);
        free(buffer);
        ibv_dealloc_pd(pd);
        ibv_close_device(ctx);
        ibv_free_device_list(dev_list);
        return 1;
    }

    printf("RDMA READ operation completed successfully\n");

    // Clean up
    ibv_destroy_qp(qp);
    ibv_destroy_cq(cq);
    ibv_dereg_mr(mr);
    free(buffer);
    ibv_dealloc_pd(pd);
    ibv_close_device(ctx);
    ibv_free_device_list(dev_list);

    return 0;
}