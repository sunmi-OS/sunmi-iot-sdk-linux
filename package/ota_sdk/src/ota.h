#ifndef _OTA_H_
#define _OTA_H_

#define		PRODUCT_ID_LEN	32
#define		PATH_LEN	100
#define		SN_LEN		24
#define		MODEL_LEN	16

struct upgrade_ops {
	char	confirm_download; /* 接收到升级信息后，是否需要确认后才下载固件。0-不需要确认，1-需要确认。默认为不需要确认 */
	char	confirm_install; /* 下载完成后，是否需要确认后才安装固件。0-不需要确认，1-需要确认。默认为不需要确认 */
	char	use_force_upgrade_duration; /* 强制升级时候，是否需要时间限制，0-不需要，1：需要在指定的时间段内才进行安装 */

	/**
	 * 安装升级文件的回调函数, 传入的文件是为设备制作的压缩包，需要进行解压，提取等操作，安装完成后是否需要重启有设备决定
	 * 参数：file，升级文件
	 * 返回值：0：成功，-1：失败
	 */
	int		(*install)(char *file);
	/**
	 * 获取设备当前版本
	 * 参数：
	 * cur_ver: 当前设备的版本，出参
	 * len: cur_ver对应的buffer长度
	 * 返回值：
	 * 0: 成功，-1：失败
	 */
	int		(*get_current_version)(char *cur_ver, int len);
	/*
	* 需要确认才进行下载，如果confirm_download设置为1，则必须提供该接口的实现
	* 参数：type-升级包类型
	*/
	void	(*wait_confirm_download)(int type);
	/*
	* 需要确认才进行安装，如果confirm_install设置为1，则必须提供该接口的实现
	* 参数：type-升级包类型
	*/
	void	(*wait_confirm_install)(int type);
};

struct user_config_info {
	char	download_path[PATH_LEN]; /* 存放升级文件的绝对路径 */
	char	product_id[PRODUCT_ID_LEN]; /* 产品名字，例如printer */
	char	sn[SN_LEN];
	char	model[MODEL_LEN];
	char	has_mobile; /* 0-没有流量出口，1-有流量出口 */
	/**
	 * 1 << 0 : 支持固件升级包, 如果不设置，则默认为固件升级
	 * 1 << 1 : 支持应用升级包（可选）
	 * 1 << 2 : 支持资源升级包（可选）
	 */
	char	type_flag; /* 升级包类型标志 */

	/*
	 * 需要连接的云环境类型：如果不填写，则默认为ONLINE环境
	 * 1：DEV
	 * 2：TEST
	 * 3：UAT
	 * 4：ONLINE
	*/
	char	cloud_type;

	/*
	* 升级过程中需要注册的回调函数，这个是数组形式表示
	* 数组大小为3，表示如下：
	* 下标0：固件包升级相关的操作
	* 下标1：应用包升级相关的操作
	* 下标2：资源包升级相关的操作
	*/
	struct upgrade_ops	ops[3];

	/*
	 * 当前路由是否是移动网络，只有has_mobile为1时候，才需要实现
	 * 返回值：
	 * 1：当前的出口路由是移动网络
	 * 0：当前的出口路由不是移动网络
	*/
	int		(*current_route_is_mobile)(void);
};

/**
 * \fn        ota_init
 * \brief     OTA组件的初始化函数
 *
 * \param[in] info: 用户需要传输struct user_config_info类型的参数
 *
 * \return	-1: 失败，0-成功，主程序不能退出
 */
int	ota_init(struct user_config_info *info);

/**
 * \fn        ota_exit
 * \brief     ota SDK退出时候的资源回收
 *
 * \param[in] void:
 *
 * \return    int：0-成功，-1，失败
 */
int ota_exit(void);

/**
 * \fn        ota_check_version
 * \brief     检查版本更新
 *
 * \param[in] type: 升级包类型
 * \param[out] new_version: 返回新版本号
 * \param[in] ver_len: 存放版本号的buffer长度
 * \param[out] log: 发布log
 * \param[in] log_len: 存放log的buffer的长度
 *
 * \return    int 0-成功，-1：失败
 */
int ota_check_version(int type, char *new_version, int ver_len, char *log, int log_len);

/**
 * \fn        ota_start_download
 * \brief     开始下载更新，在客户检测完有新版本可用后，确认更新
 *
 * \param[in] type: 更新包类型
 *
 * \return    int 0-成功，-1：失败
 */
int ota_start_download(int type);

/**
 * \fn        ota_start_install
 * \brief     开始安装，对于需要确认后才安装的设备，下载完升级文件后，通知用户，用户确认后，开始安装
 *
 * \param[in] type: 升级包类型
 *
 * \return    int 0-成功，-1：失败
 */
int ota_start_install(int type);


#endif /* _OTA_H_ */
