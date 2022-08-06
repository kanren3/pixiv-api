#include "pixiv.h"

const char* hash_secret = "28c1fdd170a5204386cb1313c7077b34f83e4aaf4aa829ce78c231e05b0bae2c";
const char* client_id = "MOBrBDS8blbauoSck0ZfDbtuzpyT";
const char* client_secret = "lsACyCD94FhDUtGTXi3QzcFE2uU1hqtDaKeqrdwj";

std::string pixiv_refresh_token = "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz";
std::string pixiv_access_token = "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz";
std::string pixiv_vip_refresh_token = pixiv_refresh_token;
std::string pixiv_vip_access_token = pixiv_access_token;

nlohmann::json bookmarks_cache;

unsigned int get_genrandom()
{
    HCRYPTPROV prov = NULL;
    unsigned int genrandom = 0;

    CryptAcquireContextW(&prov, NULL, NULL, PROV_RSA_FULL, 0);

    if (prov) {
        CryptGenRandom(prov, sizeof(genrandom), (BYTE*)&genrandom);
        CryptReleaseContext(prov, 0);
    }

    if (genrandom == 0) {
        return (unsigned int)__rdtsc();
    }

    return genrandom;
}

std::string m_replace(std::string strSrc, const std::string& oldStr, const std::string& newStr, size_t count = -1)
{
    std::string strRet = strSrc;
    size_t pos = 0;
    size_t l_count = 0;
    if (-1 == count)
        count = strRet.size();
    while ((pos = strRet.find(oldStr, pos)) != std::string::npos)
    {
        strRet.replace(pos, oldStr.size(), newStr);
        if (++l_count >= count) break;
        pos += newStr.size();
    }
    return strRet;
}

std::string get_pixiv_time() {
    std::string client_time;

    time_t current_time;
    tm time_struct;

    current_time = time(0);
    localtime_s(&time_struct, &current_time);

    char tmp[64];
    strftime(tmp, sizeof(tmp), "%Y-%m-%dT%H:%M:%S+08:00", &time_struct);

    client_time = tmp;

    return client_time;
}

std::string get_pixiv_md5(std::string client_time)
{
    std::stringstream ss;
    std::string md5_string;
    std::string md5_ret;

    unsigned char md5[16] = { 0 };
    md5_string = client_time + hash_secret;

    MD5((const unsigned char*)md5_string.c_str(), md5_string.size(), md5);

    for (int i = 0; i < 16; i++)
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)md5[i];

    ss >> md5_ret;
    return md5_ret;
}

curl_slist* get_pixiv_header()
{
    curl_slist* headers = NULL;

    std::string client_time;
    std::string client_hash;

    client_time = get_pixiv_time();
    client_hash = get_pixiv_md5(client_time);

    client_time = "X-Client-Time:" + client_time;
    client_hash = "X-Client-Hash:" + client_hash;

    headers = curl_slist_append(headers, "Origin:https://oauth.secure.pixiv.net");
    headers = curl_slist_append(headers, client_time.c_str());
    headers = curl_slist_append(headers, client_hash.c_str());

    headers = curl_slist_append(headers, "User-Agent:PixivAndroidApp/5.0.115 (Android 11.0; PixivBot)");
    headers = curl_slist_append(headers, "Origin:https://oauth.secure.pixiv.net");
    headers = curl_slist_append(headers, "app-version:5.0.166");
    headers = curl_slist_append(headers, "app-os-version:Android 11");
    headers = curl_slist_append(headers, "app-os:Android");
    headers = curl_slist_append(headers, "accept-language:zh-CN");
    headers = curl_slist_append(headers, client_time.c_str());
    headers = curl_slist_append(headers, client_hash.c_str());

    return headers;
}

std::string get_pixiv_access_token(std::string login_info)
{
    std::string access_token;

    if (!login_info.empty()) {
        auto root = nlohmann::json::parse(login_info.c_str());
        access_token = root["access_token"];
    }

    return access_token;
}

std::string pixiv_update_access_token(std::string refresh_token)
{
    curl_slist* header = get_pixiv_header();

    std::string data = "get_secure_url=1";
    data = data + "&client_id=" + client_id;
    data = data + "&client_secret=" + client_secret;
    data = data + "&grant_type=refresh_token";
    data = data + "&refresh_token=" + refresh_token;

    std::string login_info;
    std::string access_token;

    if (header) {
        if (curl_get("http://blog.rin-ne.moe/test.php?" + data, &login_info, header, false)) {
            access_token = get_pixiv_access_token(login_info);
        }
        curl_slist_free_all(header);
    }

    return access_token;
}

std::string pixiv_illust()
{
    std::string illust;

    curl_slist* header = get_pixiv_header();
    std::string token = "Authorization:Bearer " + pixiv_access_token;

    if (header) {
        header = curl_slist_append(header, token.c_str());
        curl_get("http://app-api.rin-ne.moe/v1/illust/recommended?filter=for_ios&include_ranking_label=true", &illust, header, false);
        curl_slist_free_all(header);
    }

    if (illust.empty()) {
        return "";
    }

    auto root = nlohmann::json::parse(illust.c_str());
    if (root["error"].is_null()) {
        return illust;
    }

    illust.clear();
    header = get_pixiv_header();

    if (header) {
        pixiv_access_token = pixiv_update_access_token(pixiv_refresh_token);
        if (!pixiv_access_token.empty()) {
            token = "Authorization:Bearer " + pixiv_access_token;
            header = curl_slist_append(header, token.c_str());
            curl_get("http://app-api.rin-ne.moe/v1/illust/recommended?filter=for_ios&include_ranking_label=true", &illust, header, false);
            curl_slist_free_all(header);
        }
    }

    return illust;
}

std::string pixiv_autocomplete(std::string label)
{
    std::string complete_label;

    curl_slist* header = get_pixiv_header();
    std::string token = "Authorization:Bearer " + pixiv_vip_access_token;

    if (header)
    {
        header = curl_slist_append(header, token.c_str());
        curl_get(
            "https://app-api.rin-ne.moe/v2/search/autocomplete?merge_plain_keyword_results=true&word=" + AnsiToUtf8(label),
            &complete_label, header, false);
        curl_slist_free_all(header);
    }

    if (complete_label.empty()) {
        return "";
    }

    auto root = nlohmann::json::parse(complete_label.c_str());
    if (root["error"].is_null()) {
        if (root.empty() || !root["tags"].size()) {
            return "";
        }
        if (Utf8ToAnsi(root["tags"][0]["name"]).find("r18") != -1 ||
            Utf8ToAnsi(root["tags"][0]["name"]).find("R18") != -1 ||
            Utf8ToAnsi(root["tags"][0]["name"]).find("r17") != -1 ||
            Utf8ToAnsi(root["tags"][0]["name"]).find("R17") != -1) {
            return "";
        }
        return root["tags"][0]["name"];
    }

    complete_label.clear();
    header = get_pixiv_header();

    if (header) {
        pixiv_vip_access_token = pixiv_update_access_token(pixiv_vip_refresh_token);
        if (!pixiv_vip_access_token.empty()) {
            token = "Authorization:Bearer " + pixiv_vip_access_token;
            header = curl_slist_append(header, token.c_str());
            curl_get(
                "https://app-api.rin-ne.moe/v2/search/autocomplete?merge_plain_keyword_results=true&word=" + AnsiToUtf8(label),
                &complete_label, header, false);
            curl_slist_free_all(header);
        }
    }

    if (complete_label.empty()) {
        return complete_label;
    }

    root = nlohmann::json::parse(complete_label.c_str());
    if (root.empty() || !root["tags"].size()) {
        return "";
    }

    if (Utf8ToAnsi(root["tags"][0]["name"]).find("r18") != -1 ||
        Utf8ToAnsi(root["tags"][0]["name"]).find("R18") != -1 ||
        Utf8ToAnsi(root["tags"][0]["name"]).find("r17") != -1 ||
        Utf8ToAnsi(root["tags"][0]["name"]).find("R17") != -1) {
        return "";
    }

    return root["tags"][0]["name"];
}

std::string pixiv_search(std::string label)
{
    std::string search_illust;

    curl_slist* header = get_pixiv_header();
    std::string token = "Authorization:Bearer " + pixiv_vip_access_token;

    if (header)
    {
        header = curl_slist_append(header, token.c_str());
        curl_get(
            "http://app-api.rin-ne.moe/v1/search/illust?filter=for_android&merge_plain_keyword_results=true&sort=popular_desc&search_target=partial_match_for_tags&word=" + label,
            &search_illust, header, false);
        curl_slist_free_all(header);
    }

    if (search_illust.empty()) {
        return "";
    }

    auto root = nlohmann::json::parse(search_illust.c_str());
    if (root["error"].is_null()) {
        return search_illust;
    }

    search_illust.clear();
    header = get_pixiv_header();

    if (header) {
        pixiv_vip_access_token = pixiv_update_access_token(pixiv_vip_refresh_token);
        if (!pixiv_vip_access_token.empty()) {
            token = "Authorization:Bearer " + pixiv_vip_access_token;
            header = curl_slist_append(header, token.c_str());
            curl_get(
                "http://app-api.rin-ne.moe/v1/search/illust?filter=for_android&merge_plain_keyword_results=true&sort=popular_desc&search_target=partial_match_for_tags&word=" + label,
                &search_illust, header, false);
            curl_slist_free_all(header);
        }
    }

    return search_illust;
}

std::string pixiv_bookmarks()
{
    std::string bookmarks;

    curl_slist* header = get_pixiv_header();
    std::string token = "Authorization:Bearer " + pixiv_access_token;

    if (bookmarks_cache.empty() ||
        bookmarks_cache["bookmarks"].is_null() ||
        !bookmarks_cache["bookmarks"].size()) {
        return "";
    }

    if (header) {
        header = curl_slist_append(header, token.c_str());
        curl_get(bookmarks_cache["bookmarks"][get_genrandom() % bookmarks_cache["bookmarks"].size()], &bookmarks, header, false);
        curl_slist_free_all(header);
    }

    if (bookmarks.empty()) {
        return "";
    }

    auto root = nlohmann::json::parse(bookmarks.c_str());
    if (root["error"].is_null()) {
        return bookmarks;
    }

    bookmarks.clear();
    header = get_pixiv_header();

    if (header) {
        pixiv_access_token = pixiv_update_access_token(pixiv_refresh_token);
        if (!pixiv_access_token.empty()) {
            token = "Authorization:Bearer " + pixiv_access_token;
            header = curl_slist_append(header, token.c_str());
            curl_get(bookmarks_cache["bookmarks"][get_genrandom() % bookmarks_cache["bookmarks"].size()], &bookmarks, header, false);
            curl_slist_free_all(header);
        }
    }

    return bookmarks;
}

void pixiv_update_bookmarks_cache()
{
    nlohmann::json cache;
    std::string next_url = "http://app-api.rin-ne.moe/v1/user/bookmarks/illust?user_id=22851498&restrict=public&max_bookmark_id=14736421069";
    std::string bookmarks;
    curl_slist* header = get_pixiv_header();

    if (header) {
        pixiv_access_token = pixiv_update_access_token(pixiv_refresh_token);
        if (!pixiv_access_token.empty()) {
            std::string token = "Authorization:Bearer " + pixiv_access_token;
            header = curl_slist_append(header, token.c_str());

            while (!next_url.empty()) {
                bookmarks.clear();
                curl_get(next_url, &bookmarks, header, false);

                if (!bookmarks.empty()) {
                    auto root = nlohmann::json::parse(bookmarks.c_str());

                    if (!root["next_url"].is_null()) {
                        next_url = m_replace(std::string(root["next_url"]), "https://app-api.pixiv.net", "http://app-api.rin-ne.moe");
                        cache["bookmarks"] += next_url;
                    }
                    else {
                        next_url.clear();
                    }
                }
            }

            curl_slist_free_all(header);
            bookmarks_cache = cache;
        }
    }
}

bool pixiv_rand_image(std::string data, pixiv_image_info& image_info, bool r18) {
    if (!data.empty()) {
        auto root = nlohmann::json::parse(data.c_str());

        std::vector<ULONG> filter_index;

        if (root["illusts"].size()) {
            for (unsigned int i = 0; i < root["illusts"].size(); i++) {
                if (root["illusts"][i]["total_bookmarks"] > 600) {
                    if (false == r18) {
                        if (root["illusts"][i]["x_restrict"] != 0) {
                            continue;
                        }
                    }

                    bool is_filter_tag = false;

                    for (unsigned int j = 0; j < root["illusts"][i]["tags"].size(); j++) {
                        if (root["illusts"][i]["tags"][j]["name"] == u8"Âþ»­") {
                            is_filter_tag = true;
                            break;
                        }
                    }

                    if (is_filter_tag) {
                        continue;
                    }

                    filter_index.push_back(i);
                }
            }
        }

        if (filter_index.size()) {
            unsigned int index = filter_index[get_genrandom() % filter_index.size()];

            image_info.id = root["illusts"][index]["id"];
            image_info.title = root["illusts"][index]["title"];
            image_info.title = Utf8ToAnsi(image_info.title);

            if (root["illusts"][index]["meta_single_page"].size()) {
                image_info.url = root["illusts"][index]["meta_single_page"]["original_image_url"];
                image_info.name = image_info.url.substr(image_info.url.find_last_of('/') + 1);
                image_info.name = image_info.title + "_" + image_info.name;
                return true;
            }
            else if (root["illusts"][index]["meta_pages"].size()) {
                image_info.url = root["illusts"][index]["meta_pages"][0]["image_urls"]["original"];
                image_info.name = image_info.url.substr(image_info.url.find_last_of('/') + 1);
                image_info.name = image_info.title + "_" + image_info.name;
                return true;
            }
        }
    }

    return false;
}

bool pixiv_download_image(std::string image_url, std::string image_path)
{
    HANDLE ImageHandle = INVALID_HANDLE_VALUE;

    ImageHandle = CreateFileA(
        image_path.c_str(),
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL);

    if (INVALID_HANDLE_VALUE != ImageHandle) {
        CloseHandle(ImageHandle);
        return true;
    }

    std::string image_file;

    if (!image_url.empty()) {
        curl_slist* header = NULL;
        header = curl_slist_append(header, "Referer:https://www.pixiv.net");

        if (header) {
            if (image_url.find("i.pximg.net") != -1) {
                std::string my_image_url = m_replace(image_url, "https://i.pximg.net", "http://image.rin-ne.moe");
                curl_get(my_image_url, &image_file, header, false);
            }
            curl_slist_free_all(header);
        }
    }

    if (image_file.size()) {
        ImageHandle = CreateFileA(
            image_path.c_str(),
            GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ,
            NULL,
            CREATE_ALWAYS,
            FILE_ATTRIBUTE_NORMAL,
            NULL);

        if (INVALID_HANDLE_VALUE != ImageHandle) {
            ULONG NumberOfBytesWritten = 0;

            WriteFile(
                ImageHandle,
                image_file.c_str(),
                (ULONG)image_file.size(),
                &NumberOfBytesWritten,
                NULL);

            CloseHandle(ImageHandle);

            if (NumberOfBytesWritten > 0) {
                return true;
            }
        }
    }

    return false;
}

bool pixiv_add_favorite(uint64_t id)
{
    pixiv_access_token = pixiv_update_access_token(pixiv_refresh_token);
    curl_slist* header = get_pixiv_header();
    std::string token = "Authorization:Bearer " + pixiv_access_token;

    if (header) {
        header = curl_slist_append(header, token.c_str());

        std::string data = "restrict=public&illust_id=" + std::to_string(id);
        std::string ret;

        curl_post("http://app-api.rin-ne.moe/v2/illust/bookmark/add", &ret, data, header, false);
        curl_slist_free_all(header);

        if (strstr(ret.c_str(), "error")) {
            return false;
        }
    }

    return true;
}