/**
 *
 * 阿里云盘同步工具
 *
 */
const { SHA256 } = require("crypto-js");
const { ecdsaSign, publicKeyCreate } = require("secp256k1");
const { v4 } = require("uuid");
const getUuid = require("uuid-by-string");
const log = require("./log")("main");

async function main() {
  const localdir = process.argv[2];
  const FETCH_COUNT = 2;
  const fetchTasks = {};
  startFetchTask(fetchTasks, localdir, FETCH_COUNT);
  while (true) {
    try {
      const accessToken = await refreshToken();
      const remoteTree = await refreshRemoteTree(accessToken);
      const fetchList = filterFilesNeedFetched(remoteTree, localdir);
      if (fetchList.length > 0) {
        await fetchFiles(fetchList, fetchTasks);
      }
    } catch (err) {
      log.error({ err }, "unexpected error");
    }
    if (Object.keys(fetchTasks).length == 0) {
      log.info("sleep 1 min(s)");
    }
    await new Promise((r) => setTimeout(r, 60 * 1000));
  }
}

async function deleleRemote(task) {
  if (task.path.startsWith("/keep/")) {
    return;
  }
  const info = await aliFetch("https://api.aliyundrive.com/v2/batch", {
    requests: [
      {
        body: {
          drive_id: task.drive_id,
          file_id: task.file_id,
        },
        headers: { "Content-Type": "application/json" },
        id: task.file_id,
        method: "POST",
        url: "/file/delete",
      },
    ],
    resource: "file",
  });
  log.info({ info, task }, "delete remote file");
}

async function startFetchTask(tasks, localdir, limit) {
  let running = [];
  const { spawn } = require("child_process");
  while (true) {
    // check progress of running
    for (let run of running) {
      if (run.done) {
        log.info({ name: run.name }, "success");
        await deleleRemote(run);
      } else if (run.code) {
        log.info({ name: run.name, code: run.code }, "fail");
      } else {
        log.info(
          {
            name: run.name,
            bytes: run.dBytes,
            percent: run.dPercent,
            speed: run.dSpeed,
            time: run.dTime,
          },
          "progress"
        );
      }
    }
    // if someone finish, remove from tasks
    for (let run of running) {
      if (run.done) {
        delete tasks[run.file_id];
      }
    }
    running = running.filter((r) => !r.done);
    // if running less than limit, add more task
    while (running.length < limit && Object.keys(tasks).length) {
      const runningids = running.reduce((r, i) => {
        r[i.file_id] = true;
        return r;
      }, {});
      const file_id = Object.keys(tasks).filter(
        (fileid) => !runningids[fileid]
      )[0];
      if (!file_id) break;
      const file = tasks[file_id];
      const info = await aliFetch(
        "https://open.aliyundrive.com/adrive/v1.0/openFile/getDownloadUrl",
        {
          expire_sec: 36000,
          drive_id: file.drive_id,
          file_id: file.file_id,
        }
      );
      const localpath = require("path").join(localdir, file.path);
      tasks[file.file_id] = {
        ...tasks[file.file_id],
        url: info.url,
        localpath,
        name: file.name,
      };

      const aria2c = spawn("aria2c", [
        "--max-concurrent-downloads=64",
        "-c",
        "--console-log-level=notice",
        "--summary-interval=1",
        "--max-connection-per-server=16",
        "--http-no-cache=true",
        "--disk-cache=64M",
        "--no-file-allocation-limit=64M",
        "--user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.4389.82 Safari/537.36",
        "--dir=" + require("path").dirname(tasks[file_id].localpath),
        "--out=" + require("path").basename(tasks[file_id].localpath),
        tasks[file_id].url,
      ]);
      aria2c.stdout.on("data", (data) => {
        const output = data.toString();
        const progressMatch = output.match(
          /\[.* (.*)\((\d+)%\) .* DL:(.*) ETA:(.*)\]/
        );
        if (progressMatch) {
          task.dBytes = progressMatch[1];
          task.dPercent = progressMatch[2];
          task.dSpeed = progressMatch[3];
          task.dTime = progressMatch[4];
        }
      });
      aria2c.on("close", (code) => {
        if (code === 0) {
          task.done = true;
        } else {
          task.code = code;
        }
      });
      const task = {
        file_id,
        aria2c,
        ...tasks[file_id],
      };
      running.push(task);
    }
    await new Promise((r) => setTimeout(r, 1000));
  }
}

function filterFilesNeedFetched(list, local) {
  const needfilter = {};
  for (let file of list) {
    const localpath = require("path").join(local, file.path);
    if (
      require("fs").existsSync(localpath) &&
      !require("fs").existsSync(`${localpath}.aria2`)
    ) {
      deleleRemote(file);
      needfilter[file.file_id] = true;
    }
  }
  return list.filter((f) => !needfilter[f.file_id]);
}

function GetSignature(nonce, user_id, deviceId) {
  const toHex = (bytes) => {
    const hashArray = Array.from(bytes); // convert buffer to byte array
    // convert bytes to hex string
    return hashArray.map((b) => b.toString(16).padStart(2, "0")).join("");
  };
  const toU8 = (wordArray) => {
    const words = wordArray.words;
    const sigBytes = wordArray.sigBytes;
    // Convert
    const u8 = new Uint8Array(sigBytes);
    for (let i = 0; i < sigBytes; i++) {
      u8[i] = (words[i >>> 2] >>> (24 - (i % 4) * 8)) & 0xff;
    }
    return u8;
  };
  const privateKey = toU8(SHA256(user_id));
  const publicKey = "04" + toHex(publicKeyCreate(privateKey));
  const appId = "5dde4e1bdf9e4966b387ba58f4b3fdc3";
  const signature =
    toHex(
      ecdsaSign(
        toU8(SHA256(`${appId}:${deviceId}:${user_id}:${nonce}`)),
        privateKey
      ).signature
    ) + "01";
  return { signature, publicKey };
}

async function aliFetch(url, body, header) {
  let authHeader;
  if (!url.endsWith("/token")) {
    const { open, v2 } = JSON.parse(
      require("fs").readFileSync("./token.json").toString()
    );
    const user_id = v2.user_id;
    const deviceid = getUuid(user_id, 5);
    const { signature, publicKey } = GetSignature(0, user_id, deviceid);
    authHeader = {
      Authorization: `Bearer ${
        url.startsWith("https://api.aliyundrive.com/")
          ? v2.access_token
          : open.access_token
      }`,
      "x-request-id": v4().toString(),
      "x-device-id": getUuid(deviceid, 5),
      "x-signature": signature,
    };
  } else {
    authHeader = {
      referer: "https://www.aliyundrive.com/",
    };
  }
  const headers = {
    "content-type": "application/json",
    accept: "application/json, text/plain, */*",
    "accept-encoding": "gzip, deflate, br",
    "accept-language": "zh-CN,zh;q=0.9",
    "sec-ch-ua": '"Not;A=Brand";v="99", "Chromium";v="106"',
    "sec-ch-ua-platform": '"macOS"',
    "x-canary": "client=windows,app=adrive,version=v4.1.0",
    "sec-fetch-mode": "cors",
    "sec-fetch-site": "cross-site",
    "user-agent":
      "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) aDrive/4.1.0 Chrome/108.0.5359.215 Electron/22.3.1 Safari/537.36",
    ...(authHeader || {}),
    ...(header || {}),
  };
  let error;
  for (let retry = 0; retry < 3; retry++) {
    try {
      const rsp = await fetch(url, {
        method: "POST",
        body: JSON.stringify(body),
        headers,
      });
      const data = await rsp.json();
      if (data.code && data.message) {
        error = new Error(data.message);
        break;
      }
      return data;
    } catch (err) {
      error = err;
      log.error({ err }, "Unexpected Error");
      await new Promise((r) => setTimeout(r, 5000));
    }
  }
  throw error;
}

/**
 * 刷新阿里云Token，一般Token有效期为两个小时
 */
async function refreshToken() {
  if (!require("fs").existsSync("./token.json")) {
    throw new Error("No Token");
  }
  const db = JSON.parse(require("fs").readFileSync("./token.json").toString());
  const now = new Date().getTime();
  if (db.validat && db.validat - now > 10 * 60 * 1000) {
    return db;
  }

  const open = await aliFetch("https:///api-cf.nn.ci/alist/ali_open/token", {
    refresh_token: db.open.refresh_token,
    grant_type: "refresh_token",
  });

  const v2 = await aliFetch("https://auth.aliyundrive.com/v2/account/token", {
    refresh_token: db.v2.refresh_token,
    grant_type: "refresh_token",
  });

  const data = {
    ...db,
    open,
    v2,
    validat: new Date().getTime() + open.expires_in * 1000,
  };

  require("fs").writeFileSync("./token.json", JSON.stringify(data));
  return data;
}

async function refreshRemoteTree() {
  const { default_drive_id } = await aliFetch(
    "https://open.aliyundrive.com/adrive/v1.0/user/getDriveInfo"
  );
  const recurList = async (dir_id, path, result) => {
    const files = await aliFetch(
      "https://open.aliyundrive.com/adrive/v1.0/openFile/list",
      {
        drive_id: default_drive_id,
        parent_file_id: dir_id,
        marker: "",
        limit: 200,
        order_by: "name",
        order_direction: "ASC",
      }
    );
    if (files.items.length == 0 && dir_id != "root") {
      // no need to delete empty folder, so we can download new ep to same folder
      // await deleleRemote({
      //   name: path,
      //   drive_id: default_drive_id,
      //   file_id: dir_id,
      // });
    }
    for (let item of files.items) {
      const itempath = `${path}/${item.name}`;
      if (item.trashed || item.deleted) continue;
      if (item.type == "folder") {
        await recurList(item.file_id, `${path}/${item.name}`, result);
      } else {
        result.push({ ...item, path: itempath });
      }
    }
    return result;
  };
  const files = await recurList("root", "", []);
  return files;
}

async function fetchFiles(files, tasks) {
  for (let file of files) {
    if (tasks[file.file_id]) continue;
    log.info({ name: file.name }, "新发现需要下载的文件");
    tasks[file.file_id] = { ...file };
  }
}

main();
