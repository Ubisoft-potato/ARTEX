package agent

import actool "github.com/Autumn-27/norma/tool"

// Append the contract after persisted prompt/tool overrides so existing installs
// receive the new evidence rules without replacing user-written instructions.
func coverageWorkflowTools(tools []actool.CoreTool) ([]actool.CoreTool, string) {
	out := append([]actool.CoreTool(nil), tools...)
	guidance := ""
	seen := map[string]bool{}
	for i, tool := range out {
		note := ""
		switch tool.Name() {
		case "record_fact", "report_finding":
			note = "\n覆盖登记：coverage_checks 逐项提供本结果关联资产的 asset_id、十类 category、非空 evidence；每个资产和类别只登记一次。只有 done 意图下 confirmed 的明确验证项能关闭对应格子，事实另须 observed 且主 evidence 非空；一条汇总结果可包含多个检查。意图完成或计划类别不能替代证据。"
		case "coverage_matrix", "list_untested_assets":
			note = "\n统计口径：coverage_pct 是适用资产×类别格子的已验证比例。页面资产比例仅表示有非空证据的 confirmed observed 事实或 confirmed 漏洞记录（含直接来源），不代表全部类别完成。在途和历史待核实项先等待或复核，不因历史覆盖率下降批量重复探索；只按未截断矩阵的 top_gaps 选择补派方向。"
		}
		if note != "" {
			out[i] = DecorateTool(tool, tool.Description()+note, tool.InputSchema())
			if !seen[note] {
				guidance += note
				seen[note] = true
			}
		}
	}
	return out, guidance
}
