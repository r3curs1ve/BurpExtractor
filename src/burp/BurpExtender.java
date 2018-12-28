package burp;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.File;
import java.io.FileOutputStream;
import java.io.PrintWriter;
import java.util.*;
import java.util.List;

public class BurpExtender implements IBurpExtender, IContextMenuFactory, ActionListener
{
    public PrintWriter stdout = null;
    public PrintWriter stderr = null;
    private IHttpRequestResponse selectedMessage[] = null;

    @Override
    public void registerExtenderCallbacks (IBurpExtenderCallbacks callbacks)
    {
        // set our extension name
        callbacks.setExtensionName("Burp Extractor");
        this.stdout = new PrintWriter(callbacks.getStdout(), true);
        this.stderr = new PrintWriter(callbacks.getStderr(), true);
        callbacks.registerContextMenuFactory(this);
    }

    @Override
    public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
        ArrayList<JMenuItem> menu = new ArrayList<JMenuItem>();
        byte ctx = invocation.getInvocationContext();
        if (ctx == IContextMenuInvocation.CONTEXT_PROXY_HISTORY) {
            this.selectedMessage = invocation.getSelectedMessages();
            JMenuItem item = new JMenuItem("Extract file...", null);
            item.addActionListener(this);
            menu.add(item);
        }
        return menu;
    }

    @Override
    public void actionPerformed(ActionEvent e){
        File saveFile;
        String saveFilePath = null;
        JFileChooser fileChooser = new JFileChooser();
        byte[] response = this.selectedMessage[0].getResponse();
        if (fileChooser.showSaveDialog(null) == JFileChooser.APPROVE_OPTION) {
            saveFile = fileChooser.getSelectedFile();
            saveFilePath = saveFile.getAbsolutePath();
        }
        byte[] bodyResponse = Arrays.copyOfRange(response, getBodyOffset(response), response.length);
        try {
            FileOutputStream fos = new FileOutputStream(saveFilePath);
            fos.write(bodyResponse);
            fos.close();
        }catch (Exception e1){
            this.stderr.println(e1);
        }
    }

    /**
     * Search within the response the beginning
     * of the body excluding the headers
     * @param response response in byte array
     * @return offset
     */
    private int getBodyOffset(byte[] response){
        int offset;
        for (int i =0; i< response.length; i++){
            /*search first sequence \r\n */
            if (response[i] == 13 && response[i+1] == 10){
                /*search consecutive sequence \r\n */
                if (response[i+2] == 13 && response[i+3] == 10){
                    offset = i+4;
                    return offset;
                }
            }
        }
        return -1;
    }
}