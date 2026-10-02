"""Explicit, hash-pinned compatibility repairs for reviewed Kelee source defects.

Raw upstream files are never modified. No network, JavaScript, generic string
coercion or rule removal is performed. An unknown version of a reviewed filename
is blocked until its intent is reviewed again. Evidence lives in
``tests/fixtures/source-repairs/provenance.json``.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib


@dataclass(frozen=True)
class ReviewedLineRepair:
    number: int
    original: str
    replacement: str
    original_sha256: str
    replacement_sha256: str
    reason: str


@dataclass(frozen=True)
class ReviewedSourceRepair:
    source_sha256: str
    baseline_sha256: str
    repaired_sha256: str
    source_url: str
    lines: tuple[ReviewedLineRepair, ...]


BASELINE_REVISION = "a991b1d3a6b9af719dedc1be8a2c767e8f4228f0"
APPLIED_REPORT_KIND = "source-repair-applied"
BLOCKING_REPORT_KIND = "source-repair-blocked"

# These pins came from the exact 2026-10-02 10:55:24 UTC read-only snapshot.
# Do not relax a failed hash or line assertion. Review a new source explicitly.
_REPAIRS: dict[str, ReviewedSourceRepair] = {
    'BaiduMap_remove_ads.lpx': ReviewedSourceRepair(
        source_sha256='49522f58512a3d88da58eb4208793a12d1634c12a626d91d19514ac9aa627ded',
        baseline_sha256='7f38daaa731c0918ec9bae278efd1fa92cab929b22689959392a55218df92731',
        repaired_sha256='f758e0eae724a049f37eccede1801b20563070fbd9ddb39c65e68e3ef993185e',
        source_url='https://kelee.one/Tool/Loon/Lpx/BaiduMap_remove_ads.lpx',
        lines=(
            ReviewedLineRepair(
                number=20,
                original='response if ${url} ~= /^https:\\/\\/newclient\\.map\\.baidu\\.com\\/(client\\/)?usersystem\\/mine\\/page\\?/i then response.json.replace("data", "{}")',
                replacement='response if ${url} ~= /^https:\\/\\/newclient\\.map\\.baidu\\.com\\/(client\\/)?usersystem\\/mine\\/page\\?/i then response.json.jq("if (try (getpath([]) | has(\\"data\\")) catch false) then (setpath([\\"data\\"]; {})) else . end")',
                original_sha256='346146ac71805c8590a82485d654fa0e5ba739dd2b22b6008a0bf8e0bdeeb825',
                replacement_sha256='378d056fa906d5444629b3e3e767aa26cd623f59c2eb2268b14cfad23e3458fb',
                reason='Restore verified empty object/array replacement types through guarded JQ without coercing arbitrary strings.',
            ),
        ),
    ),
    'DiDi_remove_ads.lpx': ReviewedSourceRepair(
        source_sha256='bc7385fe302ae697a08c3dbf345079548917b7f2e6cc2454431417a7a601b970',
        baseline_sha256='1184e4c2a0f55e98411ca25812fc22407ee455e4cdcf295a7d9b23eb8199ca0f',
        repaired_sha256='f06307b524d4765fc3e1bff6784e6456c806685a1ee8e4c4d2f0233cb1f83541',
        source_url='https://kelee.one/Tool/Loon/Lpx/DiDi_remove_ads.lpx',
        lines=(
            ReviewedLineRepair(
                number=61,
                original='response if ${url} ~= /^https:\\/\\/htwkop\\.xiaojukeji\\.com(:443)?\\/gateway\\?api=hm\\.fa\\.querySellCardSummary/i then response.json.replace("data", "{}")',
                replacement='response if ${url} ~= /^https:\\/\\/htwkop\\.xiaojukeji\\.com(:443)?\\/gateway\\?api=hm\\.fa\\.querySellCardSummary/i then response.json.jq("if (try (getpath([]) | has(\\"data\\")) catch false) then (setpath([\\"data\\"]; {})) else . end")',
                original_sha256='deb1a383bf72d2d713b65f31b4e6475fb85545ac8609f4fccd932aa1d8f997b5',
                replacement_sha256='70b23c71b3a29a67f926f64dbf468dba776f8fde80a765e311f122ef9fb436ea',
                reason='Restore verified empty object/array replacement types through guarded JQ without coercing arbitrary strings.',
            ),
            ReviewedLineRepair(
                number=63,
                original='response if ${url} ~= /^https:\\/\\/htwkop\\.xiaojukeji\\.com(:443)?\\/gateway\\?api=hm\\.fa\\.queryWelfareCenter/i then response.json.replace("data", "{}")',
                replacement='response if ${url} ~= /^https:\\/\\/htwkop\\.xiaojukeji\\.com(:443)?\\/gateway\\?api=hm\\.fa\\.queryWelfareCenter/i then response.json.jq("if (try (getpath([]) | has(\\"data\\")) catch false) then (setpath([\\"data\\"]; {})) else . end")',
                original_sha256='a9bc2b0112c3473aeb9f749b3b8f9c5d1976e0da1c167d53f27d00a9763150db',
                replacement_sha256='e4abbebcdcd6fb15aa48a1b7ba571279538d09f076d7b1a4e1d90ebfeab1df3c',
                reason='Restore verified empty object/array replacement types through guarded JQ without coercing arbitrary strings.',
            ),
        ),
    ),
    'DigitalHeartbeat_remove_ads.lpx': ReviewedSourceRepair(
        source_sha256='802fd6e67f3aae15b144ef4da4b4cd502959a26a4fe47e422ade1072ed1f8fe0',
        baseline_sha256='f2c237ccb3d4d489693a3d3952659f38e2ca7e1114fb9d3b83ab553b9177e258',
        repaired_sha256='3a856019591eebe26f3729cce98f3dca6edd93d5bae7ce665971238a2ecc49a7',
        source_url='https://kelee.one/Tool/Loon/Lpx/DigitalHeartbeat_remove_ads.lpx',
        lines=(
            ReviewedLineRepair(
                number=14,
                original='response if ${url} ~= /^https:\\/\\/api-changzheng\\.chinaath\\.com\\/changzheng-common-proxy-api\\/api\\/advertising\\/proxy\\/getOpenScreenAdvertising$/i then response.json.replace("data.advertisingList", "[]")',
                replacement='response if ${url} ~= /^https:\\/\\/api-changzheng\\.chinaath\\.com\\/changzheng-common-proxy-api\\/api\\/advertising\\/proxy\\/getOpenScreenAdvertising$/i then response.json.jq("if (try (getpath([\\"data\\"]) | has(\\"advertisingList\\")) catch false) then (setpath([\\"data\\",\\"advertisingList\\"]; [])) else . end")',
                original_sha256='e776436d52cfc1c5564a864a08c74f0747fed8b37fd54524be44094c5349e1da',
                replacement_sha256='dd7f94259c7ea6774d6ec4c45931ff0a80789c966bbb3b44813e630efa15d8a5',
                reason='Restore verified empty object/array replacement types through guarded JQ without coercing arbitrary strings.',
            ),
        ),
    ),
    'Keep_remove_ads.lpx': ReviewedSourceRepair(
        source_sha256='015279fe23c9b7323b2c97adf0740dc6f697ccd938675f3adfd81c22610659ff',
        baseline_sha256='2ee11147bbaefc6e6e0e4b058e461b4792e535525355e9f8bf26a794b316399e',
        repaired_sha256='3a145cee93031bb440c0a83796a4bdca6dbb687f5236ee4b32173ef2c50af623',
        source_url='https://kelee.one/Tool/Loon/Lpx/Keep_remove_ads.lpx',
        lines=(
            ReviewedLineRepair(
                number=29,
                original='response if ${url} ~= /^https:\\/\\/api\\.gotokeep\\.com\\/twins\\/v4\\/feed\\/entryDetail\\?/i then response.json.replace("data", "{}")',
                replacement='response if ${url} ~= /^https:\\/\\/api\\.gotokeep\\.com\\/twins\\/v4\\/feed\\/entryDetail\\?/i then response.json.jq("if (try (getpath([]) | has(\\"data\\")) catch false) then (setpath([\\"data\\"]; {})) else . end")',
                original_sha256='55d491da98bb934e6a66373bedcf86ee90e6f7f7301854724580eed66c50b67b',
                replacement_sha256='4e475dabac1f9bcadaf83c7e6b67c363b217b2a8d7dd12abd23d77050ea04945',
                reason='Restore verified empty object/array replacement types through guarded JQ without coercing arbitrary strings.',
            ),
        ),
    ),
    'MeiRiSaiChe_remove_ads.lpx': ReviewedSourceRepair(
        source_sha256='712c7adec68d9d749622f1ea98e79b2b8e5a61efc0cd1303525a2481365f0a31',
        baseline_sha256='4ce75f469df00a8be1b8321500b3b3dfc1993b18406dd66daa5f31a18d28949f',
        repaired_sha256='6523d92bac2cf1db43cc1c133ce153c480a71fb4e225cd7e8ced8cc70ab4da5a',
        source_url='https://kelee.one/Tool/Loon/Lpx/MeiRiSaiChe_remove_ads.lpx',
        lines=(
            ReviewedLineRepair(
                number=14,
                original='response if ${url} ~= /^https:\\/\\/api\\.romielf\\.com\\/index\\/indexv\\d\\?/i then response.json.replace(["data.advertisement", "data.listadvertising"], ["[]", "[]"])',
                replacement='response if ${url} ~= /^https:\\/\\/api\\.romielf\\.com\\/index\\/indexv\\d\\?/i then response.json.jq("if (try (getpath([\\"data\\"]) | has(\\"advertisement\\")) catch false) then (setpath([\\"data\\",\\"advertisement\\"]; [])) else . end | if (try (getpath([\\"data\\"]) | has(\\"listadvertising\\")) catch false) then (setpath([\\"data\\",\\"listadvertising\\"]; [])) else . end")',
                original_sha256='c26d40f1a77f0ce74f60d66376bf6a8fe278ef04d44516619bb1a05da0debfca',
                replacement_sha256='04aba540200d694d2174006335624937f87470bfac98353f88f6b51b02044ca4',
                reason='Restore verified empty object/array replacement types through guarded JQ without coercing arbitrary strings.',
            ),
        ),
    ),
    'PangguaiLife_remove_ads.lpx': ReviewedSourceRepair(
        source_sha256='3a9ccc82e301155d9add5e0e46ae19cc50f464d473a7e1bf7d3ce677988da2af',
        baseline_sha256='72688706325ed2901ecda13a762c07dc8ff0c00c3e7574049347f31a5a4b658f',
        repaired_sha256='80084534dbf4fee9ff7a4cb5fc310d97e370799d8250a4ed4ee9ced6417a292b',
        source_url='https://kelee.one/Tool/Loon/Lpx/PangguaiLife_remove_ads.lpx',
        lines=(
            ReviewedLineRepair(
                number=18,
                original='response if ${url} ~= /^https:\\/\\/userapi\\.qiekj\\.com\\/local-life\\/tab-order$/i then response.json.replace("data", "[]")',
                replacement='response if ${url} ~= /^https:\\/\\/userapi\\.qiekj\\.com\\/local-life\\/tab-order$/i then response.json.jq("if (try (getpath([]) | has(\\"data\\")) catch false) then (setpath([\\"data\\"]; [])) else . end")',
                original_sha256='ea147d10e4c736221978756af6041ec0bdfbd16472462d01141b6900deaea460',
                replacement_sha256='799fcb4183faa45893e15c01e5b15be3de94d375120e0ecde2c256bb9d391fae',
                reason='Restore verified empty object/array replacement types through guarded JQ without coercing arbitrary strings.',
            ),
            ReviewedLineRepair(
                number=19,
                original='response if ${url} ~= /^https:\\/\\/userapi\\.qiekj\\.com\\/integralGoods\\/queryIntegralGoodsCategoryList$/i then response.json.replace("data", "[]")',
                replacement='response if ${url} ~= /^https:\\/\\/userapi\\.qiekj\\.com\\/integralGoods\\/queryIntegralGoodsCategoryList$/i then response.json.jq("if (try (getpath([]) | has(\\"data\\")) catch false) then (setpath([\\"data\\"]; [])) else . end")',
                original_sha256='2195dc3339e8db8a5a86bb2325297e1182fbfd2ddf57960342f1d5bee08eb9a3',
                replacement_sha256='fbf9a7c317c3c0d735c39db054f05086b34b1e828b4009f5fddae9f08aef7b54',
                reason='Restore verified empty object/array replacement types through guarded JQ without coercing arbitrary strings.',
            ),
        ),
    ),
    'QiDian_remove_ads.lpx': ReviewedSourceRepair(
        source_sha256='73c6e2839aeb27619a9f4fe28302b5bf710d7e7ddb34643775074590339d3c57',
        baseline_sha256='1f78f635f43d1af35b6977e329b2eb26d7e4c05b9c5433717af39811b94ff3ef',
        repaired_sha256='3aa2fb5c6fef46bccfeedb9cf221607744c0ef7edaeaf99043215e62e7be2fb7',
        source_url='https://kelee.one/Tool/Loon/Lpx/QiDian_remove_ads.lpx',
        lines=(
            ReviewedLineRepair(
                number=28,
                original='response if ${url} ~= /^https:\\/\\/magev6\\.if\\.qidian\\.com\\/argus\\/api\\/v2\\/dailyrecommend\\/getdailyrecommend\\?/i then response.json.replace("Data.Items", "[]")',
                replacement='response if ${url} ~= /^https:\\/\\/magev6\\.if\\.qidian\\.com\\/argus\\/api\\/v2\\/dailyrecommend\\/getdailyrecommend\\?/i then response.json.jq("if (try (getpath([\\"Data\\"]) | has(\\"Items\\")) catch false) then (setpath([\\"Data\\",\\"Items\\"]; [])) else . end")',
                original_sha256='6e0fb10213784478b6693781924d8714a03212995514f1cd495e80320810b405',
                replacement_sha256='70b8e3ca581779ab8b4cac513c90b6562047b52a45513231be13792fa49a345d',
                reason='Restore verified empty object/array replacement types through guarded JQ without coercing arbitrary strings.',
            ),
        ),
    ),
    'RedPaper_remove_ads.lpx': ReviewedSourceRepair(
        source_sha256='b782ea4f811702a80f853eae8bd3a3f7a33c8a3af833f5c54fba3d75a524f646',
        baseline_sha256='54f8cbdb77c5064e3c93c4bbc7cd525ce42fceb055b41a5ea41727477b70d1da',
        repaired_sha256='da385bb13622ae145ae66ff53a809ef16f6fe60eac3f544d399d77bdd62092fa',
        source_url='https://kelee.one/Tool/Loon/Lpx/RedPaper_remove_ads.lpx',
        lines=(
            ReviewedLineRepair(
                number=25,
                original='response if ${url} ~= /^https:\\/\\/edith\\.xiaohongshu\\.com\\/api\\/sns\\/v1\\/search\\/banner_list$/i then response.json.replace("data", "{}")',
                replacement='response if ${url} ~= /^https:\\/\\/edith\\.xiaohongshu\\.com\\/api\\/sns\\/v1\\/search\\/banner_list$/i then response.json.jq("if (try (getpath([]) | has(\\"data\\")) catch false) then (setpath([\\"data\\"]; {})) else . end")',
                original_sha256='f342ec49bd3d9900af4a10aefc7302d908beb2d9ac5b9f877d7cf14f27415194',
                replacement_sha256='8ab0aa74850fa5cd9ab5ca87204bf98af69dfadef5ce51ee3d140d1c8442e1c8',
                reason='Restore verified empty object/array replacement types through guarded JQ without coercing arbitrary strings.',
            ),
            ReviewedLineRepair(
                number=26,
                original='response if ${url} ~= /^https:\\/\\/edith\\.xiaohongshu\\.com\\/api\\/sns\\/v1\\/search\\/hot_list$/i then response.json.replace("data.items", "[]")',
                replacement='response if ${url} ~= /^https:\\/\\/edith\\.xiaohongshu\\.com\\/api\\/sns\\/v1\\/search\\/hot_list$/i then response.json.jq("if (try (getpath([\\"data\\"]) | has(\\"items\\")) catch false) then (setpath([\\"data\\",\\"items\\"]; [])) else . end")',
                original_sha256='02fea0e9e520963c06d72accc417586f022bbea1ae2d00195228a75e0e24d9f9',
                replacement_sha256='291514cbb5a2ca387fa0b32e63338eeebb838ed835f30664b8e7af898ae30029',
                reason='Restore verified empty object/array replacement types through guarded JQ without coercing arbitrary strings.',
            ),
            ReviewedLineRepair(
                number=27,
                original='response if ${url} ~= /^https:\\/\\/edith\\.xiaohongshu\\.com\\/api\\/sns\\/v4\\/search\\/hint/i then response.json.replace("data.hint_words", "[]")',
                replacement='response if ${url} ~= /^https:\\/\\/edith\\.xiaohongshu\\.com\\/api\\/sns\\/v4\\/search\\/hint/i then response.json.jq("if (try (getpath([\\"data\\"]) | has(\\"hint_words\\")) catch false) then (setpath([\\"data\\",\\"hint_words\\"]; [])) else . end")',
                original_sha256='fff50b583a9991f05ec5475a4f4a18ce57ec037a9b4e781f221d57f1f9ad24aa',
                replacement_sha256='3656a082287baca7e2b406305ffd06e295546886607140962ff9e496444671f9',
                reason='Restore verified empty object/array replacement types through guarded JQ without coercing arbitrary strings.',
            ),
            ReviewedLineRepair(
                number=28,
                original='response if ${url} ~= /^https:\\/\\/edith\\.xiaohongshu\\.com\\/api\\/sns\\/v4\\/search\\/trending\\?/i then response.json.replace(["data.queries", "data.hint_word"], ["[]", "{}"])',
                replacement='response if ${url} ~= /^https:\\/\\/edith\\.xiaohongshu\\.com\\/api\\/sns\\/v4\\/search\\/trending\\?/i then response.json.jq("if (try (getpath([\\"data\\"]) | has(\\"queries\\")) catch false) then (setpath([\\"data\\",\\"queries\\"]; [])) else . end | if (try (getpath([\\"data\\"]) | has(\\"hint_word\\")) catch false) then (setpath([\\"data\\",\\"hint_word\\"]; {})) else . end")',
                original_sha256='3cebc1e4327d014b473d7a6a25ecc2c2e0a763b88d15073f188fcfecd91daf09',
                replacement_sha256='022eed26dfd9620eaee14a4e64671aa53fab26d25a09e16be15ef3b8d55929b6',
                reason='Restore verified empty object/array replacement types through guarded JQ without coercing arbitrary strings.',
            ),
        ),
    ),
    'JiaXiaoDrive_remove_ads.lpx': ReviewedSourceRepair(
        source_sha256='b6c356cb056a05bcaae4985bbdb23f520dfbb250d0582bc7ee8f235298073eb1',
        baseline_sha256='ab74079290e3f5efc10245846a1905bb81b8e654a7962f8ca27112fe21a44dd4',
        repaired_sha256='68e073cd8578df5d738e8087e629c6fe16ec2da4f962e24e4c8c7fce59963597',
        source_url='https://kelee.one/Tool/Loon/Lpx/JiaXiaoDrive_remove_ads.lpx',
        lines=(
            ReviewedLineRepair(
                number=19,
                original='response if ${url} ~= /http-response/i then response.json.delete("^https:\\\\/\\\\/api\\\\.ksedt\\\\.com\\\\/api\\\\/config\\\\/")',
                replacement='response if ${url} ~= /^https:\\/\\/api\\.ksedt\\.com\\/api\\/config\\//i then response.json.delete(["result.homead","result.h5_promotion_page","result.advert_interval","result.abtest_h5url","result.launchApp","result.goucheConfig","result.gouche","result.mainLiveConfig","result.discover","result.adSdkSwitch4testPointVideo","result.adSdkSwitch4simulationExam","result.examPageLoadADSwitch"])',
                original_sha256='810c7722bc13127d094d0f9841aad8b7452fc51bf0e636ef53bae84d6dc7ee0c',
                replacement_sha256='334c271bb55f88b2dc89d375856e0187844010cf67d7226ad5bfa3f67691dbb9',
                reason='Restore the verified URL guard and all twelve baseline JSON deletion paths lost in the malformed migration.',
            ),
        ),
    ),
    'SF-Express_remove_ads.lpx': ReviewedSourceRepair(
        source_sha256='fdc1c6a5ff266785c1c2bf38ecbf7600f2fbe142f966400b6c8468b9a307262d',
        baseline_sha256='82d52eead6393a69c9d64950628d932e098717e744d1b9c3cddb33fb93b89444',
        repaired_sha256='9dc49e1a9413dd714bea7d5c6801e01c1a40ffe44b9766f6562c26f9d5e71c03',
        source_url='https://kelee.one/Tool/Loon/Lpx/SF-Express_remove_ads.lpx',
        lines=(
            ReviewedLineRepair(
                number=18,
                original='response if ${url} ~= /^https:\\/\\/ucmp(-static)?\\.sf-express\\.com\\/proxy\\/ccspBase\\/module-config\\/(login\\/)?query\\?/i then response.body.mock("json", "{\\"version\\":\\"2.0\\",\\"success\\":true,\\"obj\\":[{\\"positionName\\":\\"APP2025\\",\\"positionChannel\\":\\"app\\",\\"sceneList\\":[{\\"urlType\\":\\"webview\\",\\"sceneCode\\":\\"ddcb36295d5d2939ba4bbe2e5e02a4d8\\",\\"extendField1\\":\\"{\\\\\\"boundApp\\\\\\":\\\\\\"Android,iOS\\\\\\"}\\",\\"id\\":29130,\\"extendFieldOneDTO\\":{\\"boundApp\\":\\"Android,iOS\\"},\\"seq\\":0,\\"sceneName\\":\\"寄快递\\",\\"updateTime\\":\\"2026-02-06 18:55:15\\",\\"url\\":\\"{ \\\\\\"needLogin\\\\\\": true, \\\\\\"classify\\\\\\": \\\\\\"MY_SERVICE\\\\\\", \\\\\\"params\\\\\\": { \\\\\\"jumpName\\\\\\": \\\\\\"快速寄件\\\\", 200)',
                replacement='response if ${url} ~= /^https:\\/\\/ucmp(-static)?\\.sf-express\\.com\\/proxy\\/ccspBase\\/module-config\\/(login\\/)?query\\?/i then response.body.mock("json", "{\\"version\\":\\"2.0\\",\\"success\\":true,\\"obj\\":[{\\"positionName\\":\\"APP2025\\",\\"positionChannel\\":\\"app\\",\\"sceneList\\":[{\\"urlType\\":\\"webview\\",\\"sceneCode\\":\\"ddcb36295d5d2939ba4bbe2e5e02a4d8\\",\\"extendField1\\":\\"{\\\\\\"boundApp\\\\\\":\\\\\\"Android,iOS\\\\\\"}\\",\\"id\\":29130,\\"extendFieldOneDTO\\":{\\"boundApp\\":\\"Android,iOS\\"},\\"seq\\":0,\\"sceneName\\":\\"寄快递\\",\\"updateTime\\":\\"2026-02-06 18:55:15\\",\\"url\\":\\"{ \\\\\\"needLogin\\\\\\": true, \\\\\\"classify\\\\\\": \\\\\\"MY_SERVICE\\\\\\", \\\\\\"params\\\\\\": { \\\\\\"jumpName\\\\\\": \\\\\\"快速寄件\\\\\\" } }\\",\\"positionId\\":\\"app-index-2025\\",\\"createTime\\":\\"2026-02-06 18:55:15\\",\\"background\\":\\"https://ucmp-static.sf-express.com/sfoss/ad-act/infoflow/15FF24D0AC094758ACD2600331214A1A.png\\",\\"typeId\\":\\"primary\\",\\"typeLabel\\":\\"一级入口\\",\\"status\\":1},{\\"urlType\\":\\"webview\\",\\"sceneCode\\":\\"71e3cad43945360ffa6299644d9fbce0\\",\\"extendField1\\":\\"{\\\\\\"boundApp\\\\\\":\\\\\\"Android,iOS\\\\\\"}\\",\\"id\\":29132,\\"extendFieldOneDTO\\":{\\"boundApp\\":\\"Android,iOS\\"},\\"seq\\":2,\\"sceneName\\":\\"校园一级\\",\\"updateTime\\":\\"2026-02-06 18:55:16\\",\\"url\\":\\"{\\\\\\"needLogin\\\\\\":true,\\\\\\"clientVersionCode\\\\\\": \\\\\\"1096920\\\\\\",\\\\\\"params\\\\\\":{\\\\\\"isEncode\\\\\\":true,\\\\\\"domain\\\\\\":\\\\\\"mcs-mimp-web.sf-express.com\\\\\\",\\\\\\"extendNoSign\\\\\\":\\\\\\"&source=SFAPP&bizCode=6196@UHB1a1hjd0V1RDR4a3RTRnJhMmJVMTA1SnhreUh6Vk43U0xYMWZ6aWk4Wk1XclA3MXFRT3dhUjZnK29KY2lSZg==\\\\\\",\\\\\\"isLanguage\\\\\\":true,\\\\\\"needReqTime\\\\\\":\\\\\\"1\\\\\\",\\\\\\"needSign\\\\\\":true,\\\\\\"source\\\\\\":{\\\\\\"uri\\\\\\":\\\\\\"https://mcs-mimp-web.sf-express.com/mcs-mimp/share/app/shareRedirect\\\\\\"},\\\\\\"mustUserInfo\\\\\\":true},\\\\\\"pageRoute\\\\\\":\\\\\\"WedViewPage\\\\\\"}\\",\\"positionId\\":\\"app-index-2025\\",\\"createTime\\":\\"2026-02-06 18:55:16\\",\\"background\\":\\"https://ucmp-static.sf-express.com/sfoss/ad-act/infoflow/04560114349E4DCF9F9C82348D5FD5B8.png\\",\\"typeId\\":\\"primary\\",\\"typeLabel\\":\\"一级入口\\",\\"status\\":1},{\\"urlType\\":\\"webview\\",\\"sceneCode\\":\\"d3cf8b8a7be155edc8d507b21a491401\\",\\"extendField1\\":\\"{\\\\\\"boundApp\\\\\\":\\\\\\"Android,iOS\\\\\\"}\\",\\"id\\":29134,\\"extendFieldOneDTO\\":{\\"boundApp\\":\\"Android,iOS\\"},\\"seq\\":4,\\"sceneName\\":\\"寄大件\\",\\"updateTime\\":\\"2026-02-06 18:55:17\\",\\"url\\":\\"{ \\\\\\"params\\\\\\": { \\\\\\"source\\\\\\": { \\\\\\"uri\\\\\\": \\\\\\"https://ucmp.sf-express.com/we/cxmodules/large-items-aggregation\\\\\\" }, \\\\\\"needSign\\\\\\": true, \\\\\\"isEncode\\\\\\": true }, \\\\\\"needLogin\\\\\\": true, \\\\\\"pageRoute\\\\\\": \\\\\\"WedViewPage\\\\\\", \\\\\\"clientVersionCode\\\\\\": 1095600 }\\",\\"positionId\\":\\"app-index-2025\\",\\"createTime\\":\\"2026-02-06 18:55:17\\",\\"background\\":\\"https://ucmp-static.sf-express.com/sfoss/ad-act/infoflow/A234EFA247C04A6A91DEBD06E91BA24B.png\\",\\"typeId\\":\\"primary\\",\\"typeLabel\\":\\"一级入口\\",\\"status\\":1},{\\"icon\\":\\"https://ucmp-static.sf-express.com/sfoss/ad-act/infoflow/781D64D298F148F7892A7E705D8C2B1D.png\\",\\"urlType\\":\\"webview\\",\\"sceneCode\\":\\"b83fbeb018acfafc5ad8b38362cf684a\\",\\"extendField1\\":\\"{\\\\\\"boundApp\\\\\\":\\\\\\"Android,iOS\\\\\\"}\\",\\"id\\":29136,\\"extendFieldOneDTO\\":{\\"boundApp\\":\\"Android,iOS\\"},\\"seq\\":6,\\"sceneName\\":\\"同城急送\\",\\"subjectTagContent\\":\\"低至3折\\",\\"updateTime\\":\\"2025-11-10 10:45:03\\",\\"url\\":\\"{ \\\\\\"params\\\\\\": { \\\\\\"title\\\\\\": \\\\\\"同城急送\\\\\\", \\\\\\"source\\\\\\": { \\\\\\"uri\\\\\\": \\\\\\"https://shopic.sf-express.com/crm/webapp?platform=syapp\\\\\\" }, \\\\\\"domain\\\\\\": \\\\\\"shopic.sf-express.com\\\\\\", \\\\\\"launch\\\\\\": { \\\\\\"text\\\\\\": \\\\\\"服务提示：深圳市顺丰同城物流有限公司向您提供相关服务并承担法律责任\\\\\\", \\\\\\"onlyOne\\\\\\": true, \\\\\\"delayTime\\\\\\": 2, \\\\\\"iconUrl\\\\\\": \\\\\\"https://ucmp-static.sf-express.com/appmsoss/app-ms/manage/f082fcd320254d5aaca06316fff9ef8c.jpeg\\\\\\" } }, \\\\\\"needLogin\\\\\\": true, \\\\\\"pageRoute\\\\\\": \\\\\\"WedViewPage\\\\\\" }\\",\\"subjectContent\\":\\"同城急送\\",\\"positionId\\":\\"app-index-2025\\",\\"createTime\\":\\"2025-11-10 10:45:03\\",\\"typeId\\":\\"business\\",\\"typeLabel\\":\\"BU业务入口\\",\\"status\\":1},{\\"icon\\":\\"https://ucmp-static.sf-express.com/sfoss/ad-act/infoflow/52B9DF2E9E6742DFAD64EF4F786CBDE5.png\\",\\"urlType\\":\\"webview\\",\\"sceneCode\\":\\"eabfae966908cdf6947f67bd58618b80\\",\\"extendField1\\":\\"{\\\\\\"boundApp\\\\\\":\\\\\\"Android,iOS\\\\\\"}\\",\\"id\\":29137,\\"extendFieldOneDTO\\":{\\"boundApp\\":\\"Android,iOS\\"},\\"seq\\":7,\\"sceneName\\":\\"港澳台寄递聚合\\",\\"updateTime\\":\\"2025-11-10 10:45:07\\",\\"url\\":\\"{ \\\\\\"params\\\\\\": { \\\\\\"source\\\\\\": { \\\\\\"uri\\\\\\": \\\\\\"https://ucmp.sf-express.com/wxaccess/app/auth/CX_REGION_APP\\\\\\" }, \\\\\\"needSign\\\\\\": true, \\\\\\"extendNoSign\\\\\\": \\\\\\"&reserved=scene%3Dhmt%26source%3Dsfapp\\\\\\", \\\\\\"isEncode\\\\\\": true }, \\\\\\"needLogin\\\\\\": true, \\\\\\"pageRoute\\\\\\": \\\\\\"WedViewPage\\\\\\", \\\\\\"clientVersionCode\\\\\\": 1092600 }\\",\\"subjectContent\\":\\"港澳台寄递\\",\\"positionId\\":\\"app-index-2025\\",\\"createTime\\":\\"2025-11-10 10:45:07\\",\\"typeId\\":\\"business\\",\\"typeLabel\\":\\"BU业务入口\\",\\"status\\":1},{\\"icon\\":\\"https://ucmp-static.sf-express.com/sfoss/ad-act/infoflow/6392EB5E406C4815AC447454FE22AED6.png\\",\\"urlType\\":\\"webview\\",\\"sceneCode\\":\\"51473b493e2e6fdf6ad5be62a816e34b\\",\\"extendField1\\":\\"{\\\\\\"boundApp\\\\\\":\\\\\\"Android,iOS\\\\\\"}\\",\\"id\\":29138,\\"extendFieldOneDTO\\":{\\"boundApp\\":\\"Android,iOS\\"},\\"seq\\":8,\\"sceneName\\":\\"国际寄递聚合\\",\\"updateTime\\":\\"2025-11-10 10:45:08\\",\\"url\\":\\"{ \\\\\\"params\\\\\\": { \\\\\\"source\\\\\\": { \\\\\\"uri\\\\\\": \\\\\\"https://ucmp.sf-express.com/wxaccess/app/auth/CX_REGION_APP\\\\\\" }, \\\\\\"needSign\\\\\\": true, \\\\\\"extendNoSign\\\\\\": \\\\\\"&reserved=scene%3Dinternational%26source%3Dsfapp\\\\\\", \\\\\\"isEncode\\\\\\": true }, \\\\\\"needLogin\\\\\\": true, \\\\\\"pageRoute\\\\\\": \\\\\\"WedViewPage\\\\\\", \\\\\\"clientVersionCode\\\\\\": 1092600 }\\",\\"subjectContent\\":\\"国际寄递\\",\\"positionId\\":\\"app-index-2025\\",\\"createTime\\":\\"2025-11-10 10:45:08\\",\\"typeId\\":\\"business\\",\\"typeLabel\\":\\"BU业务入口\\",\\"status\\":1},{\\"icon\\":\\"https://ucmp-static.sf-express.com/sfoss/ad-act/infoflow/FD5BD3BB180F4144BA66DAF9206407DA.png\\",\\"urlType\\":\\"webview\\",\\"sceneCode\\":\\"7a41415450ee35202fb1c9788ea8451f\\",\\"extendField1\\":\\"{\\\\\\"boundApp\\\\\\":\\\\\\"Android,iOS\\\\\\"}\\",\\"id\\":29139,\\"extendFieldOneDTO\\":{\\"boundApp\\":\\"Android,iOS\\"},\\"seq\\":9,\\"sceneName\\":\\"冷链服务\\",\\"updateTime\\":\\"2025-11-10 10:47:57\\",\\"url\\":\\"{\\\\n \\\\\\"routeName\\\\\\":\\\\\\"WedViewPage\\\\\\",\\\\n \\\\\\"params\\\\\\":{\\\\n  \\\\\\"source\\\\\\":{\\\\n   \\\\\\"uri\\\\\\":\\\\\\"https://ucmp.sf-express.com/wxaccess/app/auth/COLD_ENTRY\\\\\\"\\\\n  },\\\\n  \\\\\\"needSign\\\\\\":true,\\\\n  \\\\\\"extendNoSign\\\\\\":\\\\\\"&reserved=source%3Dsfapp\\\\\\",\\\\n  \\\\\\"isEncode\\\\\\":true\\\\n },\\\\n \\\\\\"needLogin\\\\\\":true\\\\n}\\",\\"subjectContent\\":\\"冷链服务\\",\\"positionId\\":\\"app-index-2025\\",\\"createTime\\":\\"2025-11-10 10:47:57\\",\\"typeId\\":\\"business\\",\\"typeLabel\\":\\"BU业务入口\\",\\"status\\":1},{\\"icon\\":\\"https://ucmp-static.sf-express.com/sfoss/ad-act/infoflow/905E0C4475AF44FB94AB9D3BDD5E52AD.png\\",\\"urlType\\":\\"webview\\",\\"sceneCode\\":\\"4b7e32005e03a27212dcb65130261768\\",\\"extendField1\\":\\"{\\\\\\"boundApp\\\\\\":\\\\\\"Android,iOS\\\\\\"}\\",\\"id\\":29140,\\"extendFieldOneDTO\\":{\\"boundApp\\":\\"Android,iOS\\"},\\"seq\\":10,\\"sceneName\\":\\"货运用车\\",\\"updateTime\\":\\"2025-11-26 17:38:32\\",\\"url\\":\\"{\\\\\\"needLogin\\\\\\":true,\\\\\\"params\\\\\\":{\\\\\\"isEncode\\\\\\":true,\\\\\\"signOption\\\\\\":{\\\\\\"header\\\\\\":true},\\\\\\"source\\\\\\":{\\\\\\"uri\\\\\\":\\\\\\"https://ucmp.sf-express.com/wxaccess/weixin/activity/acsp-tc-h5?channelCode=cx_app\\\\\\"}},\\\\\\"pageRoute\\\\\\":\\\\\\"WedViewPage\\\\\\", \\\\\\"clientVersionCode\\\\\\": 1098500}\\",\\"subjectContent\\":\\"货运用车\\",\\"positionId\\":\\"app-index-2025\\",\\"createTime\\":\\"2025-11-26 17:38:32\\",\\"typeId\\":\\"business\\",\\"typeLabel\\":\\"BU业务入口\\",\\"status\\":1},{\\"icon\\":\\"https://ucmp-static.sf-express.com/sfoss/ad-act/infoflow/A3E53FCA8C43433B8357EA57C29DFDAC.png\\",\\"urlType\\":\\"webview\\",\\"sceneCode\\":\\"0df8bc7fe4dd8da1becaa565ae20a853\\",\\"extendField1\\":\\"{\\\\\\"boundApp\\\\\\":\\\\\\"Android,iOS\\\\\\"}\\",\\"id\\":29141,\\"extendFieldOneDTO\\":{\\"boundApp\\":\\"Android,iOS\\"},\\"seq\\":11,\\"sceneName\\":\\"扫码寄件\\",\\"updateTime\\":\\"2025-11-10 10:45:04\\",\\"url\\":\\"{ \\\\\\"needLogin\\\\\\":true, \\\\\\"pageRoute\\\\\\":\\\\\\"OtherScanner\\\\\\", \\\\\\"params\\\\\\":{} }\\",\\"subjectContent\\":\\"扫码寄件\\",\\"positionId\\":\\"app-index-2025\\",\\"createTime\\":\\"2025-11-10 10:45:04\\",\\"typeId\\":\\"featuredShipping\\",\\"typeLabel\\":\\"特色寄\\",\\"status\\":1},{\\"icon\\":\\"https://ucmp-static.sf-express.com/sfoss/ad-act/infoflow/23A69EB0535B44E48AD54306ED04B6DA.png\\",\\"urlType\\":\\"webview\\",\\"sceneCode\\":\\"26d1dd3ac7109ae291897706e01dbbe8\\",\\"extendField1\\":\\"{\\\\\\"boundApp\\\\\\":\\\\\\"Android,iOS\\\\\\"}\\",\\"id\\":29142,\\"extendFieldOneDTO\\":{\\"boundApp\\":\\"Android,iOS\\"},\\"seq\\":12,\\"sceneName\\":\\"批量寄\\",\\"updateTime\\":\\"2025-11-10 10:45:05\\",\\"url\\":\\"{ \\\\\\"needLogin\\\\\\":true, \\\\\\"pageRoute\\\\\\":\\\\\\"PlaceOrder\\\\\\", \\\\\\"params\\\\\\":{ \\\\\\"jumpName\\\\\\":\\\\\\"批量寄\\\\\\" } }\\",\\"subjectContent\\":\\"批量寄\\",\\"positionId\\":\\"app-index-2025\\",\\"createTime\\":\\"2025-11-10 10:45:05\\",\\"typeId\\":\\"featuredShipping\\",\\"typeLabel\\":\\"特色寄\\",\\"status\\":1},{\\"icon\\":\\"https://ucmp-static.sf-express.com/sfoss/ad-act/infoflow/E344425C8BB244D6964FFFB0B108CF2F.png\\",\\"urlType\\":\\"webview\\",\\"sceneCode\\":\\"da6824bb91638c9c71b33ee461b65751\\",\\"extendField1\\":\\"{\\\\\\"boundApp\\\\\\":\\\\\\"Android,iOS\\\\\\"}\\",\\"id\\":29143,\\"extendFieldOneDTO\\":{\\"boundApp\\":\\"Android,iOS\\"},\\"seq\\":13,\\"sceneName\\":\\"丰巢寄件\\",\\"updateTime\\":\\"2025-11-10 10:45:06\\",\\"url\\":\\"{ \\\\\\"needLogin\\\\\\":true, \\\\\\"pageRoute\\\\\\":\\\\\\"PlaceOrder\\\\\\", \\\\\\"params\\\\\\":{ \\\\\\"jumpName\\\\\\":\\\\\\"丰巢寄件\\\\\\" } }\\",\\"subjectContent\\":\\"丰巢寄件\\",\\"positionId\\":\\"app-index-2025\\",\\"createTime\\":\\"2025-11-10 10:45:06\\",\\"typeId\\":\\"featuredShipping\\",\\"typeLabel\\":\\"特色寄\\",\\"status\\":1},{\\"icon\\":\\"https://ucmp-static.sf-express.com/sfoss/ad-act/infoflow/E1A0E6FC7EE348BB89668ABB8C11ABA0.png\\",\\"urlType\\":\\"webview\\",\\"sceneCode\\":\\"d8c6e0777988662130261992e8723f92\\",\\"extendField1\\":\\"{\\\\\\"boundApp\\\\\\":\\\\\\"Android,iOS\\\\\\"}\\",\\"id\\":29144,\\"extendFieldOneDTO\\":{\\"boundApp\\":\\"Android,iOS\\"},\\"seq\\":14,\\"sceneName\\":\\"服务点自寄\\",\\"updateTime\\":\\"2025-11-20 18:13:51\\",\\"url\\":\\"{ \\\\\\"needLogin\\\\\\":true, \\\\\\"pageRoute\\\\\\":\\\\\\"PlaceOrder\\\\\\", \\\\\\"params\\\\\\":{ \\\\\\"orderStyle\\\\\\":1,\\\\\\"nServicePoint\\\\\\" :true}}\\",\\"subjectContent\\":\\"服务点自寄\\",\\"positionId\\":\\"app-index-2025\\",\\"createTime\\":\\"2025-11-20 18:13:51\\",\\"typeId\\":\\"featuredShipping\\",\\"typeLabel\\":\\"特色寄\\",\\"status\\":1},{\\"icon\\":\\"https://ucmp-static.sf-express.com/sfoss/ad-act/infoflow/895DB023B42D4E72A69EB59942441B27.png\\",\\"graySceneId\\":\\"ereturn-stop\\",\\"urlType\\":\\"webview\\",\\"sceneCode\\":\\"b43d71308c69324de5010852b7d5a897\\",\\"extendField1\\":\\"{\\\\\\"boundApp\\\\\\":\\\\\\"Android,iOS\\\\\\"}\\",\\"id\\":29145,\\"extendFieldOneDTO\\":{\\"boundApp\\":\\"Android,iOS\\"},\\"seq\\":15,\\"sceneName\\":\\"网购退货\\",\\"updateTime\\":\\"2026-02-11 19:24:46\\",\\"url\\":\\"{\\\\\\"needLogin\\\\\\":true,\\\\\\"params\\\\\\":{\\\\\\"isEncode\\\\\\":true,\\\\\\"domain\\\\\\":\\\\\\"mcs-mimp-web.sf-express.com\\\\\\",\\\\\\"extendNoSign\\\\\\":\\\\\\"&source=SFAPP&bizCode=6107@Mk5hR09FSGJlUXVxVTNSUUtFRWJ4cEpBUzh2U2pUVlVWNGlYdVFmbEhQOGxlV1dYeGMwTWxXL25Pb0lXLzZqdkkrMFI0WDdSWk44MlZhZDk3dGl3NHNYT1hDV1NOS1Z0V2YwcDZLb2c0WGR5Y0pnNUs3bGtibDA1RWdsTkFmbCs=\\\\\\",\\\\\\"isLanguage\\\\\\":true,\\\\\\"needReqTime\\\\\\":\\\\\\"1\\\\\\",\\\\\\"needSign\\\\\\":true,\\\\\\"source\\\\\\":{\\\\\\"uri\\\\\\":\\\\\\"https://mcs-mimp-web.sf-express.com/mcs-mimp/share/app/shareRedirect\\\\\\"},\\\\\\"mustUserInfo\\\\\\":true},\\\\\\"pageRoute\\\\\\":\\\\\\"WedViewPage\\\\\\"}\\",\\"subjectContent\\":\\"网购退货\\",\\"positionId\\":\\"app-index-2025\\",\\"createTime\\":\\"2026-02-11 19:24:46\\",\\"typeId\\":\\"featuredShipping\\",\\"typeLabel\\":\\"特色寄\\",\\"status\\":0},{\\"icon\\":\\"https://ucmp-static.sf-express.com/sfoss/ad-act/infoflow/B6CD5E4A8A034850A85A1ACD08E85321.png\\",\\"urlType\\":\\"webview\\",\\"sceneCode\\":\\"b5c548c150ca439568161a24dc212ade\\",\\"extendField1\\":\\"{\\\\\\"boundApp\\\\\\":\\\\\\"Android,iOS\\\\\\"}\\",\\"id\\":29147,\\"extendFieldOneDTO\\":{\\"boundApp\\":\\"Android,iOS\\"},\\"seq\\":17,\\"sceneName\\":\\"寄快递二级\\",\\"updateTime\\":\\"2025-11-10 11:03:34\\",\\"url\\":\\"{ \\\\\\"needLogin\\\\\\":true,\\\\\\"clientVersionCode\\\\\\": \\\\\\"1096920\\\\\\", \\\\\\"classify\\\\\\":\\\\\\"MY_SERVICE\\\\\\", \\\\\\"pageRoute\\\\\\":\\\\\\"PlaceOrder\\\\\\", \\\\\\"params\\\\\\":{ \\\\\\"orderStyle\\\\\\":0 } }\\",\\"subjectContent\\":\\"寄快递\\",\\"positionId\\":\\"app-index-2025\\",\\"createTime\\":\\"2025-11-10 11:03:34\\",\\"typeId\\":\\"featuredShipping\\",\\"typeLabel\\":\\"特色寄\\",\\"status\\":1},{\\"icon\\":\\"https://ucmp-static.sf-express.com/sfoss/ad-act/infoflow/1C97E1AD956E4BA096E167170A412274.png\\",\\"graySceneId\\":\\"handling-documents\\",\\"urlType\\":\\"webview\\",\\"sceneCode\\":\\"3df254ebeee83568c56308bff1f7e86f\\",\\"extendField1\\":\\"{\\\\\\"boundApp\\\\\\":\\\\\\"Android,iOS\\\\\\"}\\",\\"id\\":29148,\\"extendFieldOneDTO\\":{\\"boundApp\\":\\"Android,iOS\\"},\\"seq\\":18,\\"sceneName\\":\\"跑腿服务\\",\\"subjectTagContent\\":\\"帮我拿\\",\\"updateTime\\":\\"2025-11-11 15:46:58\\",\\"url\\":\\"{ \\\\\\"needLogin\\\\\\":true, \\\\\\"classify\\\\\\":\\\\\\"MY_SERVICE\\\\\\", \\\\\\"pageRoute\\\\\\":\\\\\\"RunErrands\\\\\\", \\\\\\"params\\\\\\":{ \\\\\\"title\\\\\\":\\\\\\"跑腿服务\\\\\\" } }\\",\\"subjectContent\\":\\"跑腿服务\\",\\"positionId\\":\\"app-index-2025\\",\\"createTime\\":\\"2025-11-11 15:46:58\\",\\"typeId\\":\\"featuredShipping\\",\\"typeLabel\\":\\"特色寄\\",\\"status\\":0},{\\"icon\\":\\"https://ucmp-static.sf-express.com/sfoss/ad-act/infoflow/1071250D3EB947C0AFFFFD9514A01F4B.png\\",\\"urlType\\":\\"webview\\",\\"sceneCode\\":\\"5eaa2c330b1fc1a5ed7dab99c6617620\\",\\"extendField1\\":\\"{\\\\\\"boundApp\\\\\\":\\\\\\"Android,iOS\\\\\\"}\\",\\"id\\":29149,\\"extendFieldOneDTO\\":{\\"boundApp\\":\\"Android,iOS\\"},\\"seq\\":19,\\"sceneName\\":\\"礼物寄递\\",\\"subjectTagContent\\":\\"送心意\\",\\"updateTime\\":\\"2025-11-10 11:01:32\\",\\"url\\":\\"{ \\\\\\"needLogin\\\\\\":true, \\\\\\"pageRoute\\\\\\":\\\\\\"PlaceOrder\\\\\\", \\\\\\"clientVersionCode\\\\\\": \\\\\\"1094200\\\\\\", \\\\\\"params\\\\\\":{ \\\\\\"title\\\\\\": \\\\\\"\\\\\\", \\\\\\"jumpName\\\\\\":\\\\\\"无忧送礼\\\\\\" } }\\",\\"subjectContent\\":\\"礼品寄\\",\\"positionId\\":\\"app-index-2025\\",\\"createTime\\":\\"2025-11-10 11:01:32\\",\\"typeId\\":\\"featuredShipping\\",\\"typeLabel\\":\\"特色寄\\",\\"status\\":1},{\\"icon\\":\\"https://ucmp-static.sf-express.com/sfoss/ad-act/infoflow/78D77A27A5D149D6B5A514C104DE1112.png\\",\\"urlType\\":\\"webview\\",\\"sceneCode\\":\\"3b2705c751c4e259cab3ddcafdc91302\\",\\"extendField1\\":\\"{\\\\\\"boundApp\\\\\\":\\\\\\"Android,iOS\\\\\\"}\\",\\"id\\":29150,\\"extendFieldOneDTO\\":{\\"boundApp\\":\\"Android,iOS\\"},\\"seq\\":20,\\"sceneName\\":\\"雪具寄\\",\\"updateTime\\":\\"2025-11-10 10:47:56\\",\\"url\\":\\"{ \\\\\\"needLogin\\\\\\": true, \\\\\\"pageRoute\\\\\\": \\\\\\"PlaceOrder\\\\\\", \\\\\\"clientVersionCode\\\\\\":1096000,\\\\\\"params\\\\\\":{ \\\\\\"title\\\\\\": \\\\\\"雪具寄\\\\\\", \\\\\\"orderStyle\\\\\\" : 0, \\\\\\"pickupEntranceCode\\\\\\": \\\\\\"XUEJUJIAPP\\\\\\", \\\\\\"tabIndex\\\\\\": { \\\\\\"first\\\\\\": -1, \\\\\\"second\\\\\\": -1 } } }\\",\\"subjectContent\\":\\"雪具寄\\",\\"positionId\\":\\"app-index-2025\\",\\"createTime\\":\\"2025-11-10 10:47:56\\",\\"typeId\\":\\"featuredShipping\\",\\"typeLabel\\":\\"特色寄\\",\\"status\\":1},{\\"icon\\":\\"https://ucmp-static.sf-express.com/sfoss/ad-act/infoflow/3A47AF90F705440DA5250D6FCDEB1798.png\\",\\"urlType\\":\\"webview\\",\\"sceneCode\\":\\"3e4fc16a26b75a72a68009c93eef6457\\",\\"extendField1\\":\\"{\\\\\\"boundApp\\\\\\":\\\\\\"Android,iOS\\\\\\"}\\",\\"id\\":29151,\\"extendFieldOneDTO\\":{\\"boundApp\\":\\"Android,iOS\\"},\\"seq\\":21,\\"sceneName\\":\\"行李寄存\\",\\"subjectTagContent\\":\\"行李管家\\",\\"updateTime\\":\\"2025-11-10 10:47:55\\",\\"url\\":\\"{\\\\\\"needLogin\\\\\\":true,\\\\\\"params\\\\\\":{\\\\\\"isEncode\\\\\\":true,\\\\\\"domain\\\\\\":\\\\\\"ucmp.sf-express.com\\\\\\",\\\\\\"extendNoSign\\\\\\":\\\\\\"&source=SFAPP&bizCode=6115@eHg3d1NZT1pPZU9SclhnYkhMUG9rNWRKK2FlZ1l5cklwNXUrbHVnbFYrTFVRRkVoZGRyRTltbjRCeDN6S1dwSQ==\\\\\\",\\\\\\"isLanguage\\\\\\":true,\\\\\\"needReqTime\\\\\\":\\\\\\"1\\\\\\",\\\\\\"needSign\\\\\\":true,\\\\\\"source\\\\\\":{\\\\\\"uri\\\\\\":\\\\\\"https://ucmp.sf-express.com/wxaccess/app/auth/cultural-tourism-agg\\\\\\"},\\\\\\"mustUserInfo\\\\\\":true},\\\\\\"pageRoute\\\\\\":\\\\\\"WedViewPage\\\\\\"}\\",\\"subjectContent\\":\\"轻松行\\",\\"positionId\\":\\"app-index-2025\\",\\"createTime\\":\\"2025-11-10 10:47:55\\",\\"typeId\\":\\"featuredShipping\\",\\"typeLabel\\":\\"特色寄\\",\\"status\\":1},{\\"icon\\":\\"https://ucmp-static.sf-express.com/sfoss/ad-act/infoflow/7842459BBA804A3DB3408EB00007AA7C.png\\",\\"urlType\\":\\"webview\\",\\"sceneCode\\":\\"94c646cdbc3e11682dc1fe5232119702\\",\\"extendField1\\":\\"{\\\\\\"boundApp\\\\\\":\\\\\\"Android,iOS\\\\\\"}\\",\\"id\\":29152,\\"extendFieldOneDTO\\":{\\"boundApp\\":\\"Android,iOS\\"},\\"seq\\":22,\\"sceneName\\":\\"校园专区\\",\\"updateTime\\":\\"2025-12-15 20:46:41\\",\\"url\\":\\"{\\\\\\"needLogin\\\\\\":true,\\\\\\"params\\\\\\":{\\\\\\"isEncode\\\\\\":true,\\\\\\"domain\\\\\\":\\\\\\"mcs-mimp-web.sf-express.com\\\\\\",\\\\\\"extendNoSign\\\\\\":\\\\\\"&source=SFAPP&bizCode=%7B%22path%22%3A%22%2Forigin%2Fa%2Fmimp%2Dmember%2Dright%2FcampusZone%22%2C%22linkCode%22%3A%22SFAC20250321142854983%22%2C%22supportShare%22%3A%22YES%22%2C%22from%22%3A%22campuscxapp250321%22%7D\\\\\\",\\\\\\"isLanguage\\\\\\":true,\\\\\\"needReqTime\\\\\\":\\\\\\"1\\\\\\",\\\\\\"needSign\\\\\\":true,\\\\\\"source\\\\\\":{\\\\\\"uri\\\\\\":\\\\\\"https://mcs-mimp-web.sf-express.com/mcs-mimp/share/app/activityRedirect\\\\\\"},\\\\\\"mustUserInfo\\\\\\":true},\\\\\\"pageRoute\\\\\\":\\\\\\"WedViewPage\\\\\\",\\\\\\"clientVersionCode\\\\\\": \\\\\\"1097520\\\\\\"}\\",\\"subjectContent\\":\\"校园专享\\",\\"positionId\\":\\"app-index-2025\\",\\"createTime\\":\\"2025-12-15 20:46:41\\",\\"typeId\\":\\"featuredShipping\\",\\"typeLabel\\":\\"特色寄\\",\\"status\\":1},{\\"icon\\":\\"https://ucmp-static.sf-express.com/sfoss/ad-act/infoflow/00A17C284C654B17982A619CD6BC6E8C.png\\",\\"urlType\\":\\"webview\\",\\"sceneCode\\":\\"4dfb74ad847240da74ef779a71983e23\\",\\"extendField1\\":\\"{\\\\\\"boundApp\\\\\\":\\\\\\"Android,iOS\\\\\\"}\\",\\"id\\":29153,\\"extendFieldOneDTO\\":{\\"boundApp\\":\\"Android,iOS\\"},\\"seq\\":23,\\"sceneName\\":\\"代收货款\\",\\"updateTime\\":\\"2025-11-10 11:03:29\\",\\"url\\":\\"{\\\\n    \\\\\\"params\\\\\\": {\\\\n        \\\\\\"title\\\\\\": \\\\\\"代收货款\\\\\\"\\\\n    },\\\\n    \\\\\\"needLogin\\\\\\": true,\\\\n    \\\\\\"pageRoute\\\\\\": \\\\\\"WedViewPage\\\\\\",\\\\n    \\\\\\"appId\\\\\\": \\\\\\"202112031150033323\\\\\\",\\\\n    \\\\\\"isFromShare\\\\\\": true\\\\n}\\",\\"subjectContent\\":\\"代收货款\\",\\"positionId\\":\\"app-index-2025\\",\\"createTime\\":\\"2025-11-10 11:03:29\\",\\"typeId\\":\\"featuredShipping\\",\\"typeLabel\\":\\"特色寄\\",\\"status\\":1},{\\"icon\\":\\"https://ucmp-static.sf-express.com/sfoss/ad-act/infoflow/2E5BA6994EB748A0B54ABC4E77BC8404.png\\",\\"urlType\\":\\"webview\\",\\"sceneCode\\":\\"61a4cc135ec404643b365081dd07a47b\\",\\"extendField1\\":\\"{\\\\\\"boundApp\\\\\\":\\\\\\"Android,iOS\\\\\\"}\\",\\"id\\":29154,\\"extendFieldOneDTO\\":{\\"boundApp\\":\\"Android,iOS\\"},\\"seq\\":24,\\"sceneName\\":\\"生鲜寄\\",\\"updateTime\\":\\"2025-11-10 10:47:54\\",\\"url\\":\\"{ \\\\\\"needLogin\\\\\\":true, \\\\\\"pageRoute\\\\\\":\\\\\\"PlaceOrder\\\\\\", \\\\\\"params\\\\\\":{ \\\\\\"jumpName\\\\\\":\\\\\\"生鲜\\\\\\" }, \\\\\\"clientVersionCode\\\\\\":\\\\\\"1093300\\\\\\"}\\",\\"subjectContent\\":\\"生鲜寄\\",\\"positionId\\":\\"app-index-2025\\",\\"createTime\\":\\"2025-11-10 10:47:54\\",\\"typeId\\":\\"featuredShipping\\",\\"typeLabel\\":\\"特色寄\\",\\"status\\":1},{\\"icon\\":\\"https://ucmp-static.sf-express.com/sfoss/ad-act/infoflow/EDC51E372833483DA66B148F0CC38E1B.png\\",\\"graySceneId\\":\\"campus_new_combine\\",\\"urlType\\":\\"webview\\",\\"sceneCode\\":\\"b95064ca6295426c4417a37ac1d867e4\\",\\"extendField1\\":\\"{\\\\\\"boundApp\\\\\\":\\\\\\"Android,iOS\\\\\\"}\\",\\"id\\":29155,\\"extendFieldOneDTO\\":{\\"boundApp\\":\\"Android,iOS\\"},\\"seq\\":25,\\"sceneName\\":\\"新校园专区\\",\\"updateTime\\":\\"2025-11-10 14:26:45\\",\\"url\\":\\"{\\\\\\"needLogin\\\\\\":true,\\\\\\"params\\\\\\":{\\\\\\"isEncode\\\\\\":true,\\\\\\"domain\\\\\\":\\\\\\"mcs-mimp-web.sf-express.com\\\\\\",\\\\\\"extendNoSign\\\\\\":\\\\\\"&source=SFAPP&bizCode=%7B%22path%22%3A%22%2Forigin%2Fa%2Fmimp%2Dmember%2Dright%2FcampusZone%22%2C%22linkCode%22%3A%22SFAC20250321142854983%22%2C%22supportShare%22%3A%22YES%22%2C%22from%22%3A%22campuscxapp250321%22%7D\\\\\\",\\\\\\"isLanguage\\\\\\":true,\\\\\\"needReqTime\\\\\\":\\\\\\"1\\\\\\",\\\\\\"needSign\\\\\\":true,\\\\\\"source\\\\\\":{\\\\\\"uri\\\\\\":\\\\\\"https://mcs-mimp-web.sf-express.com/mcs-mimp/share/app/activityRedirect\\\\\\"},\\\\\\"mustUserInfo\\\\\\":true},\\\\\\"pageRoute\\\\\\":\\\\\\"WedViewPage\\\\\\",\\\\\\"clientVersionCode\\\\\\": \\\\\\"1097520\\\\\\"}\\",\\"subjectContent\\":\\"校园专享\\",\\"positionId\\":\\"app-index-2025\\",\\"createTime\\":\\"2025-11-10 14:26:45\\",\\"typeId\\":\\"featuredShipping\\",\\"typeLabel\\":\\"特色寄\\",\\"status\\":0},{\\"icon\\":\\"https://ucmp-static.sf-express.com/sfoss/ad-act/infoflow/898C16DD4D044C4AAAC8D6747E46176B.png\\",\\"urlType\\":\\"webview\\",\\"sceneCode\\":\\"18d0097382b3a34785905db39f7e0fbb\\",\\"extendField1\\":\\"{\\\\\\"boundApp\\\\\\":\\\\\\"Android,iOS\\\\\\"}\\",\\"id\\":29156,\\"extendFieldOneDTO\\":{\\"boundApp\\":\\"Android,iOS\\"},\\"seq\\":26,\\"sceneName\\":\\"顺丰集运\\",\\"updateTime\\":\\"2025-11-10 11:03:30\\",\\"url\\":\\"{\\\\n    \\\\\\"params\\\\\\":{\\\\n        \\\\\\"title\\\\\\":\\\\\\"顺丰集运\\\\\\"\\\\n    },\\\\n    \\\\\\"needLogin\\\\\\":true,\\\\n    \\\\\\"pageRoute\\\\\\":\\\\\\"WedViewPage\\\\\\",\\\\n    \\\\\\"appId\\\\\\":\\\\\\"202112201117443948\\\\\\",\\\\n\\\\\\"isFromShare\\\\\\":true\\\\n}\\",\\"subjectContent\\":\\"顺丰集运\\",\\"positionId\\":\\"app-index-2025\\",\\"createTime\\":\\"2025-11-10 11:03:30\\",\\"typeId\\":\\"featuredShipping\\",\\"typeLabel\\":\\"特色寄\\",\\"status\\":1},{\\"icon\\":\\"https://ucmp-static.sf-express.com/sfoss/ad-act/infoflow/DF2501714CE24B7888FA3B3B4F3DCBDB.png\\",\\"urlType\\":\\"webview\\",\\"sceneCode\\":\\"357d56bec5fecc0d7aa91c6ed950155a\\",\\"extendField1\\":\\"{\\\\\\"boundApp\\\\\\":\\\\\\"Android,iOS\\\\\\"}\\",\\"id\\":29157,\\"extendFieldOneDTO\\":{\\"boundApp\\":\\"Android,iOS\\"},\\"seq\\":27,\\"sceneName\\":\\"微友寄\\",\\"updateTime\\":\\"2025-11-10 11:03:31\\",\\"url\\":\\"{\\\\n\\\\\\"params\\\\\\": {\\\\n\\\\\\"appInfo\\\\\\": {\\\\n\\\\\\"appId\\\\\\": \\\\\\"__UNI__4148A0B\\\\\\",\\\\n\\\\\\"redirectPath\\\\\\": \\\\\\"\\\\\\",\\\\n\\\\\\"version\\\\\\": {\\\\n\\\\\\"name\\\\\\": \\\\\\"1.8.6\\\\\\",\\\\n\\\\\\"code\\\\\\": \\\\\\"186\\\\\\"\\\\n},\\\\n\\\\\\"zipUrl\\\\\\": \\\\\\"https://ccsp-egmas-static.sf-express.com/sfoss/download/WeFriendMail/CCMAS/微友寄-186.zip\\\\\\"\\\\n},\\\\n\\\\\\"needSign\\\\\\": true,\\\\n\\\\\\"mustUserInfo\\\\\\": true,\\\\n\\\\\\"isEncode\\\\\\": true,\\\\n\\\\\\"extendSign\\\\\\": \\\\\\"\\\\\\",\\\\n\\\\\\"extendNoSign\\\\\\": \\\\\\"\\\\\\"\\\\n},\\\\n\\\\\\"needLogin\\\\\\": true,\\\\n\\\\\\"pageRoute\\\\\\": \\\\\\"UniAppStartController\\\\\\",\\\\n\\\\\\"clientVersionCode\\\\\\": \\\\\\"1093000\\\\\\"\\\\n}\\",\\"subjectContent\\":\\"微友寄\\",\\"positionId\\":\\"app-index-2025\\",\\"createTime\\":\\"2025-11-10 11:03:31\\",\\"typeId\\":\\"featuredShipping\\",\\"typeLabel\\":\\"特色寄\\",\\"status\\":1},{\\"icon\\":\\"https://ucmp-static.sf-express.com/sfoss/ad-act/infoflow/4D055100B7D249FD8BE46667B409ED7D.png\\",\\"urlType\\":\\"webview\\",\\"sceneCode\\":\\"aa5344ca1a2e17ac68a867d47b5eca4c\\",\\"extendField1\\":\\"{\\\\\\"boundApp\\\\\\":\\\\\\"Android,iOS\\\\\\"}\\",\\"id\\":29159,\\"extendFieldOneDTO\\":{\\"boundApp\\":\\"Android,iOS\\"},\\"seq\\":29,\\"sceneName\\":\\"球包寄\\",\\"updateTime\\":\\"2026-01-21 18:52:18\\",\\"url\\":\\"{ \\\\\\"needLogin\\\\\\":true, \\\\\\"pageRoute\\\\\\":\\\\\\"GolfPreOrderPage\\\\\\", \\\\\\"clientVersionCode\\\\\\":1098700,\\\\\\"params\\\\\\":{ \\\\\\"title\\\\\\":\\\\\\"球包寄\\\\\\"}}\\",\\"subjectContent\\":\\"球包寄\\",\\"positionId\\":\\"app-index-2025\\",\\"createTime\\":\\"2026-01-21 18:52:18\\",\\"typeId\\":\\"featuredShipping\\",\\"typeLabel\\":\\"特色寄\\",\\"status\\":1}],\\"id\\":\\"app-index-2025\\"},{\\"positionName\\":\\"跑腿服务聚合页-APP\\",\\"positionChannel\\":\\"app\\",\\"sceneList\\":[{\\"buttonName\\":\\"去使用\\",\\"icon\\":\\"https://ucmp-static.sf-express.com/sfoss/ad-act/infoflow/C463C2F7093A4D1092843F7A1E187E20.png\\",\\"graySceneId\\":\\"handling-documents\\",\\"urlType\\":\\"webview\\",\\"subSubjectContent\\":\\"香港证件代领，专业又安全\\",\\"sceneCode\\":\\"3dc41995434864d883d6627607cf0260\\",\\"extendField1\\":\\"{\\\\\\"boundApp\\\\\\":\\\\\\"Android,iOS\\\\\\"}\\",\\"id\\":28090,\\"extendFieldOneDTO\\":{\\"boundApp\\":\\"Android,iOS\\"},\\"seq\\":0,\\"sceneName\\":\\"代领证件\\",\\"updateTime\\":\\"2025-11-28 18:47:05\\",\\"url\\":\\"{\\\\n \\\\\\"params\\\\\\": {\\\\n  \\\\\\"source\\\\\\": {\\\\n   \\\\\\"uri\\\\\\": \\\\\\"https://ucmp.sf-express.com/wechat-act/weixin/activity/ibu-cios-h5-scan?originCode=HK_DBZJ\\\\\\"\\\\n  },\\\\n\\\\\\"signOption\\\\\\": {\\\\n        \\\\\\"header\\\\\\": true\\\\n      },\\\\n  \\\\\\"isEncode\\\\\\": true\\\\n },\\\\n \\\\\\"needLogin\\\\\\": true,\\\\n \\\\\\"pageRoute\\\\\\": \\\\\\"WedViewPage\\\\\\"\\\\n}\\",\\"subjectContent\\":\\"代领证件\\",\\"positionId\\":\\"run-errands-app\\",\\"createTime\\":\\"2025-11-28 18:47:05\\",\\"status\\":0},{\\"buttonName\\":\\"去使用\\",\\"icon\\":\\"https://ucmp-static.sf-express.com/sfoss/ad-act/infoflow/9EADDED6E6EA4FDCAF3AA138CBDA52D6.png\\",\\"urlType\\":\\"webview\\",\\"subSubjectContent\\":\\"附近物品代取代送\\",\\"sceneCode\\":\\"3af8615506597215e3051ddb9704604f\\",\\"extendField1\\":\\"{\\\\\\"boundApp\\\\\\":\\\\\\"Android,iOS\\\\\\"}\\",\\"id\\":28091,\\"extendFieldOneDTO\\":{\\"boundApp\\":\\"Android,iOS\\"},\\"seq\\":1,\\"sceneName\\":\\"帮我拿\\",\\"updateTime\\":\\"2025-12-18 16:29:14\\",\\"url\\":\\"{\\\\n \\\\\\"params\\\\\\": {\\\\n  \\\\\\"source\\\\\\": {\\\\n   \\\\\\"uri\\\\\\": \\\\\\"https://ucmp.sf-express.com/wxaccess/weixin/auth2?state=CARRY-H5&source=APP\\\\\\"\\\\n  },\\\\n\\\\\\"signOption\\\\\\": {\\\\n        \\\\\\"header\\\\\\": true\\\\n      },\\\\n  \\\\\\"isEncode\\\\\\": true\\\\n },\\\\n \\\\\\"needLogin\\\\\\": true,\\\\n \\\\\\"pageRoute\\\\\\": \\\\\\"WedViewPage\\\\\\"\\\\n}\\",\\"subjectContent\\":\\"帮我拿\\",\\"positionId\\":\\"run-errands-app\\",\\"createTime\\":\\"2025-12-18 16:29:14\\",\\"status\\":1}],\\"id\\":\\"run-errands-app\\"},{\\"positionName\\":\\"文旅专区聚合页-APP\\",\\"positionChannel\\":\\"app\\",\\"sceneList\\":[{\\"icon\\":\\"https://ucmp-static.sf-express.com/sfoss/ad-act/infoflow/9FD5B3B79E494E54A5440CE858DB6764.png\\",\\"urlType\\":\\"webview\\",\\"subSubjectContent\\":\\"一键下单，上门取送\\",\\"sceneCode\\":\\"7c53ff994fecf766d5122ae78a43bba3\\",\\"id\\":28809,\\"authType\\":1,\\"seq\\":0,\\"sceneName\\":\\"行李寄递\\",\\"updateTime\\":\\"2026-02-09 09:39:55\\",\\"subjectContent\\":\\"行李寄递\\",\\"positionId\\":\\"travel_aggregation_page-app\\",\\"createTime\\":\\"2026-02-09 09:39:55\\",\\"status\\":1},{\\"icon\\":\\"https://ucmp-static.sf-express.com/sfoss/ad-act/infoflow/49FB62B6CFAE46BA8054E07C784C077E.png\\",\\"urlType\\":\\"webview\\",\\"subSubjectContent\\":\\"随存随取，安全省心\\",\\"sceneCode\\":\\"ff1ad1f975a57617c6347a843f7f464c\\",\\"id\\":28810,\\"authType\\":1,\\"seq\\":1,\\"sceneName\\":\\"行李寄存\\",\\"updateTime\\":\\"2025-12-18 11:30:10\\",\\"url\\":\\"https://ucmp.sf-express.com/wxaccess/weixin/auth2?state=cx_luggage_storage\\",\\"subjectContent\\":\\"行李寄存\\",\\"positionId\\":\\"travel_aggregation_page-app\\",\\"createTime\\":\\"2025-12-18 11:30:10\\",\\"status\\":1},{\\"icon\\":\\"https://ucmp-static.sf-express.com/sfoss/ad-act/infoflow/2DD4F459D6274638B894FC7CD07AF6EF.png\\",\\"urlType\\":\\"webview\\",\\"subSubjectContent\\":\\"专业加固，整装待发\\",\\"sceneCode\\":\\"bcdb757976b8b9c57f008c3c9a65575c\\",\\"id\\":28811,\\"authType\\":1,\\"seq\\":2,\\"sceneName\\":\\"行李打包\\",\\"updateTime\\":\\"2025-12-18 11:30:44\\",\\"url\\":\\"https://ucmp.sf-express.com/wxaccess/weixin/auth2?state=ustorage-pack-h5\\",\\"subjectContent\\":\\"行李打包\\",\\"positionId\\":\\"travel_aggregation_page-app\\",\\"createTime\\":\\"2025-12-18 11:30:44\\",\\"status\\":1},{\\"icon\\":\\"https://ucmp-static.sf-express.com/sfoss/ad-act/infoflow/AE31889D9E4B4954B8CF98B31FD6FA2C.png\\",\\"urlType\\":\\"webview\\",\\"subSubjectContent\\":\\"直送机场/酒店\\",\\"sceneCode\\":\\"39e72b24e9a6f8b3dea76f374c4ce232\\",\\"id\\":28812,\\"authType\\":1,\\"seq\\":3,\\"sceneName\\":\\"行李托运\\",\\"updateTime\\":\\"2025-12-18 11:31:58\\",\\"url\\":\\"https://ucmp.sf-express.com/wxaccess/weixin/auth2?state=ustorage-consign-h5\\",\\"subjectContent\\":\\"行李托运\\",\\"positionId\\":\\"travel_aggregation_page-app\\",\\"createTime\\":\\"2025-12-18 11:31:58\\",\\"status\\":1}],\\"id\\":\\"travel_aggregation_page-app\\"}]}", 200)',
                original_sha256='e6653a7dbfcfd1025389f1531f967fb5c2fed93842e23c2fe980e0813fec6c5e',
                replacement_sha256='1667810b395862a3b21a681ce489b1f5b034d248670888e786e770516f824aef',
                reason='Restore the exact verified complete baseline JSON body: every decoded current byte is an unchanged prefix of that body.',
            ),
        ),
    ),
}


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def apply_reviewed_source_repairs(
    filename: str, source_text: str,
) -> tuple[str, list[dict[str, str]]]:
    """Return repaired in-memory text and explicit, reproducible diagnostics.

    Unknown filenames are unaffected. For these ten reviewed filenames, only
    the pinned raw source receives a repair. Exact baseline or already-repaired
    versions are accepted unchanged. Every other version returns unchanged with
    a fatal ``source-repair-blocked`` diagnostic; callers must not publish it.
    All assertions are checked before a result or applied report is committed.
    """
    reviewed = _REPAIRS.get(filename)
    if reviewed is None:
        return source_text, []
    source_hash = _sha256(source_text)

    def blocked(reason: str, detail: str, patch: ReviewedLineRepair | None = None) -> tuple[str, list[dict[str, str]]]:
        item = {
            "file": filename,
            "kind": BLOCKING_REPORT_KIND,
            "reason": reason,
            "message": f"Reviewed source repair was not applied: {detail}. Publication must stop pending source review.",
            "line": patch.original if patch is not None else "",
            "source_url": reviewed.source_url,
            "source_sha256": source_hash,
            "expected_source_sha256": reviewed.source_sha256,
            "baseline_sha256": reviewed.baseline_sha256,
            "baseline_revision": BASELINE_REVISION,
        }
        if patch is not None:
            item["line_number"] = str(patch.number)
        return source_text, [item]

    if source_hash in (reviewed.baseline_sha256, reviewed.repaired_sha256):
        return source_text, []
    if source_hash != reviewed.source_sha256:
        return blocked("unreviewed-source-version", "the full source SHA-256 does not match the reviewed upstream version")
    numbers = [patch.number for patch in reviewed.lines]
    if len(numbers) != len(set(numbers)):
        return blocked("repair-policy-mismatch", "the repair policy contains duplicate source line numbers")

    original_lines = source_text.splitlines(keepends=True)
    for patch in reviewed.lines:
        if not 1 <= patch.number <= len(original_lines):
            return blocked("repair-policy-mismatch", "a reviewed line number is outside the source file", patch)
        line = original_lines[patch.number - 1].rstrip("\r\n")
        if line != patch.original or _sha256(line) != patch.original_sha256:
            return blocked("repair-policy-mismatch", "the original line bytes or line SHA-256 differ from reviewed evidence", patch)
        if _sha256(patch.replacement) != patch.replacement_sha256:
            return blocked("repair-policy-mismatch", "the proposed replacement line SHA-256 differs from reviewed evidence", patch)

    corrected_lines = original_lines.copy()
    for patch in reviewed.lines:
        raw = original_lines[patch.number - 1]
        ending = raw[len(raw.rstrip("\r\n")):]
        corrected_lines[patch.number - 1] = patch.replacement + ending
    corrected_text = "".join(corrected_lines)
    corrected_hash = _sha256(corrected_text)
    if corrected_hash != reviewed.repaired_sha256:
        return blocked("repair-policy-mismatch", "the repaired full-file SHA-256 differs from reviewed evidence")

    reports = []
    for patch in reviewed.lines:
        reports.append({
            "file": filename,
            "kind": APPLIED_REPORT_KIND,
            "reason": "reviewed-exact-source-repair",
            "message": patch.reason + " Applied only to the pinned source version; raw upstream bytes are retained.",
            "line": patch.original,
            "line_number": str(patch.number),
            "source_url": reviewed.source_url,
            "source_sha256": source_hash,
            "repaired_sha256": corrected_hash,
            "baseline_sha256": reviewed.baseline_sha256,
            "baseline_revision": BASELINE_REVISION,
            "original_line_sha256": patch.original_sha256,
            "replacement_line_sha256": patch.replacement_sha256,
        })
    return corrected_text, reports
