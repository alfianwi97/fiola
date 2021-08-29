package alf.security.fiola.internals.dao;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;

import org.springframework.stereotype.Repository;

import alf.security.fiola.utility.common.AppConstants;
import alf.security.fiola.utility.common.BaseComponent;
import alf.security.fiola.utility.database.DatabaseConstants;
import alf.security.fiola.utility.database.DatabaseUtil;

@Repository
public class BaseDAO extends BaseComponent {

//	public static Integer getNextSeqValue(String sequenceName) throws Exception {
//		Connection conn = null;
//		PreparedStatement ps = null;
//		ResultSet rs = null;
//		Integer retval = null;
//		try {
//			conn = DatabaseUtil.getMyCOREConnection();
//			try {
//				String sql = "SELECT nextval('" + DatabaseConstants.fiolaDbSchema + "." + sequenceName
//						+ "') as seqvalue";
//				ps = conn.prepareStatement(sql);
//				rs = ps.executeQuery();
//				if (rs.next()) {
//					String seqValue = rs.getString("seqvalue");
//					retval = Integer.valueOf(seqValue);
//				}
//			} finally {
//				if (rs != null)
//					rs.close();
//				if (ps != null)
//					ps.close();
//				if (conn != null)
//					conn.close();
//			}
//		} catch (Exception ex) {
//			transLog.error(AppConstants.EXCEPTION_DAO_HEADER, ex);
//			throw new Exception();
//		}
//		return retval;
//	}

}
