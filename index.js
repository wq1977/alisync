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

async function startFetchTask(tasks, localdir, limit) {
  let running = [];
  const { spawn } = require("child_process");
  while (true) {
    // check progress of running
    for (let run of running) {
      if (run.done) {
        log.info({ name: run.name }, "success");
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
    const { user_id, access_token } = JSON.parse(
      require("fs").readFileSync("./token.json").toString()
    );
    const deviceid = getUuid(user_id, 5);
    const { signature, publicKey } = GetSignature(0, user_id, deviceid);
    authHeader = {
      Authorization: `Bearer ${access_token}`,
      "x-request-id": v4().toString(),
      "x-device-id": getUuid(deviceid, 5),
      "x-signature": signature,
    };
  }
  const headers = {
    "content-type": "application/json",
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
      log.trace(
        { url, headers, body, rsp: data, rspHeaders: rsp.headers },
        "aliyun post"
      );
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
  const token = JSON.parse(
    require("fs").readFileSync("./token.json").toString()
  );
  const now = new Date().getTime();
  if (token.validat && token.validat - now > 10 * 60 * 1000) {
    return token.access_token;
  }

  const data = await aliFetch("https:///api-cf.nn.ci/alist/ali_open/token", {
    refresh_token: token.refresh_token,
    grant_type: "refresh_token",
  });
  require("fs").writeFileSync(
    "./token.json",
    JSON.stringify({
      ...token,
      ...data,
      validat: new Date().getTime() + data.expires_in * 1000,
    })
  );
  return data.access_token;
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
